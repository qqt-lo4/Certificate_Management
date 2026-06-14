function Export-ADGroupReport {
    <#
    .SYNOPSIS
        Exports Active Directory group information into a navigable HTML report for CMMC compliance.

    .DESCRIPTION
        Collects AD groups and their members based on configurable section definitions.
        Each section becomes a tab in the HTML report, with a summary table of groups
        followed by the detailed members of each group.

    .PARAMETER FolderPath
        Local destination folder for the HTML report. Must exist.

    .PARAMETER GroupSections
        Array of section definitions. Each section is a hashtable with:
            - Tab         : [string] Tab name in the report
            - Title       : [string] Display title for the groups summary
            - Include     : [string[]] One or more wildcard patterns to
                            include groups (OR logic)
            - Exclude     : [string[]] (Optional) Wildcard patterns to
                            exclude groups
            - StripPrefix : [string[]] (Optional) Prefixes stripped from
                            group names for display

    .PARAMETER Server
        Optional AD server / domain hint. When omitted, every domain of
        the current forest is queried (cross-forest group resolution).

    .PARAMETER Credential
        Optional credentials for AD queries.

    .OUTPUTS
        [System.IO.FileInfo] - the generated HTML file.

    .EXAMPLE
        $sections = @(
            @{ Tab = "pam"; Title = "PAM Access"; Include = @("pam_pi_*"); StripPrefix = @("pam_pi_") }
            @{ Tab = "vpn"; Title = "VPN Access"; Include = @("acces_vpn_*", "access_vpn_*"); Exclude = @("*_disabled"); StripPrefix = @("acces_vpn_", "access_vpn_") }
        )
        Export-ADGroupReport -FolderPath C:\Exports -GroupSections $sections

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-06-04, Loic Ade) - Initial version. Extracted from the
                             legacy Export-ADConfiguration (Project_UDF) -
                             keeps only the per-section group catalog logic.
                             Security / GPO / Inventory ship in
                             Export-ADSecurityReport, NTP in
                             Export-ADTimeReport.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$FolderPath,

        [Parameter(Mandatory)]
        [hashtable[]]$GroupSections,

        [string]$Server,

        [PSCredential]$Credential
    )

    Begin {
        if (-not (Test-Path $FolderPath -PathType Container)) {
            throw "Folder does not exist: $FolderPath"
        }
    }

    Process {
        # Wall-clock measurement of the full Process block. Local to
        # this invocation: each call to the cmdlet (and there's one
        # call per checked export type) creates its own Stopwatch, so
        # the AD/BeyondTrust/Filer reports each get their own
        # independent duration tooltip in their respective HTML files.
        # Read just before New-HTMLReport so the tooltip captures the
        # full data-collection cost.
        $oSW = [System.Diagnostics.Stopwatch]::StartNew()

        $sTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $sFileName = "Export_AD_Group_${sTimestamp}.html"
        $sFilePath = Join-Path $FolderPath $sFileName
        $sCallerName = "Exporting AD Groups"

        $iTotal = 0
        $iTocIndex = 0
        $aSectionFiles = @()
        $aTabs = @()

        # --- Progress phases ------------------------------------------------
        # Single source of truth for Write-Progress percentages. The export
        # is split into monotone phases whose widths reflect roughly how
        # long each phase tends to take. Sub-progress within a phase is
        # passed as 0..1 to Get-PhaseProgress; per-domain sub-phases use
        # Get-DomainStepProgress which carves the phase into equal slices
        # (one per domain) and computes the position inside the slice.
        #     Phase 1 - Groups               :   0 ..  20 %
        #     Phase 2 - Security per domain  :  20 ..  65 %
        #         Within domain slice:
        #             0.00  Default Password Policy
        #             0.05  Fine-Grained Password (PSO)
        #             0.15  OU Statistics
        #             0.40  GPO Links & Security (now also fetches per-GPO
        #                   DACLs to compute hasSecurityFilter and the
        #                   per-link reachableEnabled audience)
        #     Phase 3 - WMI Filters          :  65 ..  68 %
        #     Phase 4 - Time Synchronization :  68 ..  75 %
        #     Phase 5 - Varonis              :  75 ..  93 %
        #     Phase 6 - HTML Generation      :  93 ..  99 %
        function Get-PhaseProgress {
            Param([double]$Start, [double]$End, [double]$Sub)
            return [int]($Start + ($End - $Start) * $Sub)
        }
        function Get-DomainStepProgress {
            Param([int]$Idx, [int]$Count, [double]$Start, [double]$End, [double]$Step)
            if ($Count -lt 1) { return [int]$Start }
            $dSliceStart = $Start + (($Idx - 1) / $Count) * ($End - $Start)
            $dSliceEnd   = $Start + ($Idx / $Count) * ($End - $Start)
            return [int]($dSliceStart + ($dSliceEnd - $dSliceStart) * $Step)
        }

        # --- Common AD params ---
        $hADBaseParams = @{}
        if ($Server) { $hADBaseParams['Server'] = $Server }
        if ($Credential) { $hADBaseParams['Credential'] = $Credential }

        # --- Helper: strip prefixes from group name ---
        function Get-DisplayName {
            Param([string]$GroupName, [string[]]$Prefixes)
            if (-not $Prefixes) { return $GroupName }
            foreach ($sPrefix in ($Prefixes | Sort-Object { $_.Length } -Descending)) {
                if ($GroupName -like "$sPrefix*") {
                    return $GroupName.Substring($sPrefix.Length)
                }
            }
            return $GroupName
        }

        # --- User cache (shared across all sections) ---
        $hUserCache = @{}

        # --- Enumerate forest domains so group queries scan the whole forest,
        #     not just $env:USERDNSDOMAIN. If the caller pinned -Server, that
        #     server takes precedence and only its domain is queried.
        $aGroupQueryDomains = if ($Server) {
            @($Server)
        } else {
            @(Get-CurrentADForestDomains | ForEach-Object { $_.Name })
        }

        # ===== PROCESS EACH SECTION =====
        $iSectionIndex = 0
        foreach ($hSection in $GroupSections) {
            $iSectionIndex++
            $sTab = $hSection.Tab
            $sTitle = $hSection.Title
            $aInclude = @($hSection.Include)
            $aExclude = if ($hSection.Exclude) { @($hSection.Exclude) } else { @() }
            $aStripPrefix = if ($hSection.StripPrefix) { @($hSection.StripPrefix) } else { @() }

            if ($sTab -notin $aTabs) { $aTabs += $sTab }

            # --- Query groups matching any Include pattern ---
            Write-Progress -Activity $sCallerName -Status "$sTitle - Querying groups..." `
                -PercentComplete (Get-PhaseProgress -Start 0 -End 20 -Sub (($iSectionIndex - 1) / $GroupSections.Count))

            $aAllGroups = @()
            foreach ($sDomain in $aGroupQueryDomains) {
                foreach ($sPattern in $aInclude) {
                    try {
                        $hParams = @{
                            LDAPFilter     = "(name=$sPattern)"
                            Properties     = @('name', 'objectclass', 'distinguishedname', 'description', 'member', 'whenCreated', 'whenChanged')
                            SearchScope    = [System.DirectoryServices.SearchScope]::Subtree
                            ResultPageSize = 1000
                            Server         = $sDomain
                        }
                        if ($Credential) { $hParams['Credential'] = $Credential }
                        $aMatched = @(Get-ADGroup @hParams)
                        $aAllGroups += $aMatched
                    } catch {
                        Write-Warning "$sCallerName : Get-ADGroup ($sPattern) on $sDomain - $_"
                    }
                }
            }

            # Deduplicate (in case patterns overlap)
            if ($aInclude.Count -gt 1) {
                $hSeen = @{}
                $aAllGroups = @($aAllGroups | Where-Object {
                    $sKey = $_.adspath
                    if ($hSeen.ContainsKey($sKey)) { $false } else { $hSeen[$sKey] = $true; $true }
                })
            }

            # --- Apply exclusions ---
            if ($aExclude.Count -gt 0) {
                $aAllGroups = @($aAllGroups | Where-Object {
                    $sName = $_.name
                    -not ($aExclude | Where-Object { $sName -like $_ })
                })
            }

            if ($aAllGroups.Count -eq 0) {
                Write-Warning "$sCallerName : $sTitle - No groups found."
                continue
            }

            Write-Host "$sTitle : $($aAllGroups.Count) group(s) found" -ForegroundColor Cyan

            # --- Collect members and generate HTML per group immediately ---
            $aGroupSummary = @()
            $aMemberSectionFiles = @()

            # Reserve a slot for the summary section (will be generated after the loop)
            $iSummaryTocIndex = $iTocIndex
            $iTocIndex++

            $iGroupIndex = 0
            foreach ($oGroup in ($aAllGroups | Sort-Object name)) {
                $iGroupIndex++
                $iPercent = Get-PhaseProgress -Start 0 -End 20 `
                    -Sub ((($iSectionIndex - 1) + ($iGroupIndex / $aAllGroups.Count)) / $GroupSections.Count)
                Write-Progress -Activity $sCallerName -Status "$sTitle : $($oGroup.name) ($iGroupIndex/$($aAllGroups.Count))..." -PercentComplete $iPercent

                try {
                    $aMembersRaw = if ($oGroup.member) {
                        @(Get-GroupMembers -ADObject $oGroup -Recurse `
                            -ADObjectProperties @('name', 'objectclass', 'displayName', 'mail', 'title', 'department', 'userAccountControl', 'lastLogonTimestamp', 'sAMAccountName'))
                    } else { @() }

                    # Filter to users/computers only (exclude nested group entries), use cache
                    $aMembers = @($aMembersRaw | Where-Object { $_.objectclass -ne 'group' } | ForEach-Object {
                        $sDN = $_.distinguishedname
                        if ($sDN -and $hUserCache.ContainsKey($sDN)) {
                            $oCached = $hUserCache[$sDN]
                            $oClone = $oCached.PSObject.Copy()
                            $oClone.inheritedFrom = $_.InheritedFrom
                            $oClone
                        } else {
                            $bEnabled = if ($_.userAccountControl) { -not ($_.userAccountControl -band 2) } else { $null }
                            $dtLastLogon = if ($_.lastLogonTimestamp) {
                                try { [datetime]::FromFileTime($_.lastLogonTimestamp) } catch { $null }
                            } else { $null }

                            $oUser = [PSCustomObject][ordered]@{
                                name           = $_.name
                                samAccountName = $_.sAMAccountName
                                displayName    = $_.displayName
                                email          = $_.mail
                                title          = $_.title
                                department     = $_.department
                                enabled        = $bEnabled
                                lastLogon      = $dtLastLogon
                                objectClass    = $_.objectclass
                                inheritedFrom  = $_.InheritedFrom
                            }
                            if ($sDN) { $hUserCache[$sDN] = $oUser }
                            $oUser
                        }
                    })
                } catch {
                    Write-Warning "$sCallerName : $($oGroup.name)/Members - $_"
                    $aMembers = @()
                }

                $sDisplayName = Get-DisplayName -GroupName $oGroup.name -Prefixes $aStripPrefix

                # Resolve the group's domain from its DN (DC=foo,DC=bar -> foo.bar)
                $sGroupDomain = $null
                if ($oGroup.distinguishedname -and $oGroup.distinguishedname -match '((?:DC=[^,]+,?)+)$') {
                    $sGroupDomain = ($Matches[1] -replace 'DC=', '' -replace ',', '.').TrimEnd('.')
                }

                $aGroupSummary += [PSCustomObject][ordered]@{
                    domain      = $sGroupDomain
                    group       = $oGroup.name
                    displayName = $sDisplayName
                    description = $oGroup.description
                    memberCount = $aMembers.Count
                    whenCreated = $oGroup.whenCreated
                    whenChanged = $oGroup.whenChanged
                }

                # Generate member section HTML immediately. The section title
                # must be the raw group name so the click on the 'group' column
                # of the summary (LinkableColumns matches data-category against
                # the title verbatim) navigates here. The domain disambiguation
                # appears in the summary table column instead.
                if ($aMembers.Count -gt 0) {
                    $sId = "sec_$iTocIndex"
                    $iTocIndex++
                    $aMemberSectionFiles += ConvertTo-HTMLSectionV2 -Title $oGroup.name -Id $sId -Data $aMembers `
                        -Tab $sTab -NameProperty 'name' -DetectAllColumns
                    $iTotal += $aMembers.Count
                }
            }

            # --- Groups summary section (inserted before member sections) ---
            $sSummaryFile = ConvertTo-HTMLSectionV2 -Title $sTitle -Id "sec_$iSummaryTocIndex" -Data $aGroupSummary `
                -Tab $sTab -NameProperty 'group' -DetectAllColumns -LinkableColumns 'group'
            $aSectionFiles += $sSummaryFile
            $iTotal += $aGroupSummary.Count
            $aSectionFiles += $aMemberSectionFiles
        }

        # ===== GENERATE HTML REPORT =====
        if ($aSectionFiles.Count -eq 0) {
            Write-Warning "$sCallerName : No data collected, skipping report generation."
            return
        }

        Write-Progress -Activity $sCallerName -Status "Generating HTML report..." `
            -PercentComplete (Get-PhaseProgress -Start 93 -End 99 -Sub 0.0)

        # The group report has no domain-scoped tabs (groups span
        # the whole forest by design), so we don't build any
        # per-tab Contexts entries - the sidebar context selector
        # stays hidden.
        $oSW.Stop()
        $oReport = New-HTMLReport -Title "AD Groups Export - $sTimestamp" `
            -Brand "AD Groups" `
            -DeviceInfo "Active Directory" `
            -SectionFiles $aSectionFiles `
            -Tabs $aTabs `
            -AccentColor "#1565c0" `
            -FilePath $sFilePath `
            -ObjectCount $iTotal `
            -GenerationDuration $oSW.Elapsed

        Write-Progress -Activity $sCallerName -Completed

        Write-Host "AD Groups report exported: $sFilePath ($iTotal objects)" -ForegroundColor Green

        return $oReport
    }
}
