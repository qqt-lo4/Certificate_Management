function Export-FilerAccess {
    <#
    .SYNOPSIS
        Exports file share permissions into a navigable HTML report for CMMC compliance.

    .DESCRIPTION
        For each share definition provided, enumerates folders (DFS or direct filer)
        and retrieves NTFS permissions, then generates a single HTML report.

        Each share definition specifies Type (DFS or Filer), Server, and Path.
        - DFS: enumerates via Get-DFSFolders on the DFS server, then gets ACLs per folder
        - Filer: gets ACLs directly via Get-SharePermissions on the file server

    .PARAMETER FolderPath
        Local destination folder for the HTML report. Must exist.

    .PARAMETER ShareDefinitions
        Hashtable of share groups. Keys are display names (tab labels),
        values are arrays of hashtables with:
            - Type   : "DFS" or "Filer"
            - Server : Server name to execute on
            - Path   : UNC path (supports wildcards for DFS)

    .PARAMETER Credential
        Credentials for remote execution (DFS servers + file servers).

    .PARAMETER ExcludeInherited
        If specified, excludes inherited ACL entries. Default: $true.

    .OUTPUTS
        [System.IO.FileInfo] The generated HTML file.

    .EXAMPLE
        $shares = [ordered]@{
            "International" = @(
                @{ Type = "DFS"; Server = "DFS01"; Path = "\\domain\namespace\intl\*" }
            )
            "Dumps" = @(
                @{ Type = "DFS"; Server = "DFS01"; Path = "\\domain\namespace\securise\dump*" }
            )
            "Finance" = @(
                @{ Type = "Filer"; Server = "FILER01"; Path = "\\FILER01\Finance" }
                @{ Type = "Filer"; Server = "FILER01"; Path = "\\FILER01\Accounting" }
            )
        }
        Export-FilerAccess -FolderPath "C:\Exports" -ShareDefinitions $shares -Credential $cred

    .NOTES
        Author  : Loic Ade
        Version : 3.0.0

        3.0.0 (2026-06-10) - Decoupled from Varonis. The
                             IncludeVaronisLogs / VaronisLogsDays /
                             VaronisAPI params and the per-share
                             Varonis events block (standalone log
                             pages + iframe loader) all move to
                             Export-VaronisReport, which becomes the
                             single home for Varonis-sourced data.
                             This report now ships pure NTFS perms
                             + AD group expansion only.
        2.0.0 (2026-04-01) - Unified DFS + Filer support via ShareDefinitions
        1.1.0 (2026-04-01) - Use Get-DFSFolders + Get-DFSFolderPermissions via Invoke-Command
        1.0.0 (2026-04-01) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$FolderPath,

        [Parameter(Mandatory)]
        [hashtable]$ShareDefinitions,

        [PSCredential]$Credential,

        [bool]$ExcludeInherited = $true
    )

    Begin {
        if (-not (Test-Path $FolderPath -PathType Container)) {
            throw "Folder does not exist: $FolderPath"
        }
    }

    Process {
        $sTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $sFileName = "Export_Filers_${sTimestamp}.html"
        $sFilePath = Join-Path $FolderPath $sFileName
        $sCallerName = "Exporting Filer Access"

        $iTotal = 0
        $iTocIndex = 0
        $aSectionFiles = @()
        $aTabs = @()
        $hAllGroupIdentities = @{}  # Collect all group identityReferences across all sections
        $hIdentityTypeCache = @{}  # Cache: identity -> "group" / "user" / "other"

        $hCredParam = @{}
        if ($Credential) { $hCredParam['Credential'] = $Credential }

        # NetBIOS/DNS map built once: Resolve-ADObject uses it to
        # validate every ACE identity's domain prefix before talking
        # to AD. Sharing the map across the (potentially many)
        # per-ACE calls saves one round-trip per call.
        $hNetBIOSMap = @{}
        try { $hNetBIOSMap = Get-ADDomainNetBIOSMap @hCredParam } catch {
            Write-Warning "$sCallerName : Get-ADDomainNetBIOSMap failed ($($_.Exception.Message)) - identity-type resolution will mark every non-builtin entry as 'unknown'."
        }

        # --- Helper: resolve identity type via Resolve-ADObject (cached) ---
        # Three-way outcome:
        #   - throw from Resolve-ADObject (-StrictPrefix on unknown
        #     DOMAIN prefix) -> 'local' (server-local account like
        #     FRASN08\Administrator, or any prefix outside the AD
        #     forest).
        #   - null return (valid prefix, missing name) -> 'unknown'.
        #   - object return -> classify by objectclass.
        # Replaces the previous bare Get-ADObject -Identity <SAM>
        # -UseGlobalCatalog pattern which silently picked random GC
        # objects sharing the SAM (notably pKICertificateTemplate
        # "Administrator" under CN=Certificate Templates).
        function Resolve-IdentityType {
            Param([string]$Identity)
            if ($hIdentityTypeCache.ContainsKey($Identity)) { return $hIdentityTypeCache[$Identity] }

            # Skip well-known non-AD identities cheaply.
            if ($Identity -match '^(BUILTIN|NT AUTHORITY|CREATEUR|CREATOR)\\') {
                $hIdentityTypeCache[$Identity] = 'builtin'
                return 'builtin'
            }

            $sType = 'unknown'
            try {
                $oObj = Resolve-ADObject -Identity $Identity -NetBIOSMap $hNetBIOSMap -StrictPrefix @hCredParam
                if ($oObj) {
                    $sOC = "$($oObj.objectclass)"
                    $sType = switch -Wildcard ($sOC) {
                        'group'    { 'group' }
                        'user'     { 'user' }
                        'computer' { 'computer' }
                        default    { $sOC }
                    }
                }
            } catch {
                # Unknown domain prefix - local server account or
                # unrelated. Classification is informative, not an
                # error: the share genuinely grants access to that
                # principal even if it does not exist in AD.
                $sType = 'local'
            }

            $hIdentityTypeCache[$Identity] = $sType
            return $sType
        }

        # ===== PROCESS EACH GROUP =====
        $iGroupIndex = 0
        $iGroupCount = $ShareDefinitions.Count

        foreach ($sGroupName in $ShareDefinitions.Keys) {
            $iGroupIndex++
            $aEntries = @($ShareDefinitions[$sGroupName])

            $sTab = $sGroupName
            if ($sTab -notin $aTabs) { $aTabs += $sTab }

            Write-Progress -Activity $sCallerName -Status "$sGroupName - Collecting..." `
                -PercentComplete ([int](($iGroupIndex - 1) / $iGroupCount * 90))

            # --- Build list of folders to check: { folderName, targetServer, targetPath, dfsPath, state } ---
            $aFolders = @()

            foreach ($hEntry in $aEntries) {
                $sType = $hEntry.Type
                $sServer = $hEntry.Server
                $sPath = $hEntry.Path

                if ($sType -eq "DFS") {
                    # Enumerate via Get-DFSFolders on the DFS server
                    $aDFS = @(Get-DFSFolders -Path $sPath -ComputerName $sServer @hCredParam)
                    foreach ($o in $aDFS) {
                        $aFolders += [PSCustomObject][ordered]@{
                            folderName   = $o.folderName
                            targetServer = $o.targetServer
                            targetPath   = $o.targetPath
                            dfsPath      = $o.dfsPath
                            state        = $o.state
                            source       = "DFS ($sServer)"
                            aclServer    = $sServer
                        }
                    }
                } elseif ($sType -eq "Filer") {
                    $sLastSegment = ($sPath -split '\\')[-1]

                    if ($sLastSegment -match '\*|\?') {
                        # Wildcard: enumerate subdirectories on the filer via Invoke-Command
                        # Split path into parent + wildcard pattern
                        $sParent = $sPath.Substring(0, $sPath.LastIndexOf('\'))
                        $sPattern = $sLastSegment

                        try {
                            $aSubDirs = @(Invoke-Command -ComputerName $sServer @hCredParam -ScriptBlock {
                                param($ParentUNC, $Pattern)
                                # Resolve UNC to local path
                                if ($ParentUNC -match "^\\\\[^\\]+\\([^\\]+)(.*)$") {
                                    $sShareName = $Matches[1]
                                    $sSubPath = $Matches[2]
                                    $oShare = Get-SmbShare -Name $sShareName -ErrorAction SilentlyContinue
                                    if ($oShare) {
                                        $sLocalParent = $oShare.Path.TrimEnd('\') + $sSubPath
                                    } else {
                                        throw "Share '$sShareName' not found"
                                    }
                                } else {
                                    throw "Cannot parse UNC: $ParentUNC"
                                }

                                Get-ChildItem -Path $sLocalParent -Directory -Filter $Pattern -ErrorAction Stop | ForEach-Object {
                                    [PSCustomObject]@{
                                        Name      = $_.Name
                                        LocalPath = $_.FullName
                                    }
                                }
                            } -ArgumentList $sParent, $sPattern)

                            foreach ($oDir in $aSubDirs) {
                                $aFolders += [PSCustomObject][ordered]@{
                                    folderName   = $oDir.Name
                                    targetServer = $sServer
                                    targetPath   = "$sParent\$($oDir.Name)"
                                    dfsPath      = $null
                                    state        = $null
                                    source       = "Filer ($sServer)"
                                    aclServer    = $sServer
                                    localPath    = $oDir.LocalPath
                                }
                            }
                        } catch {
                            Write-Warning "$sCallerName : Cannot enumerate '$sPath' on $sServer - $_"
                        }
                    } else {
                        # Exact path
                        $aFolders += [PSCustomObject][ordered]@{
                            folderName   = $sLastSegment
                            targetServer = $sServer
                            targetPath   = $sPath
                            dfsPath      = $null
                            state        = $null
                            source       = "Filer ($sServer)"
                            aclServer    = $sServer
                            localPath    = $null
                        }
                    }
                } else {
                    Write-Warning "$sCallerName : Unknown type '$sType' for '$sPath'"
                }
            }

            # Deduplicate. A DFS folder with multiple targets surfaces
            # as several rows sharing the same dfsPath (Get-DFSFolders
            # emits one row per (folder, target) pair). We need ONE row
            # per folder, picking the most likely-valid target:
            #   - Online state wins over Offline/null (legacy targets
            #     that the admin "decommissioned" without removing).
            #   - Among Online tied entries we keep the first occurrence
            #     (DFS hands us its referral order; honour it).
            # Without this preference an orphan target sitting first in
            # the referral list would silently steer Get-Acl at a path
            # that no longer exists, surfacing as a confusing
            # "Cannot find path 'F:\...'" mid-report.
            if ($aFolders.Count -gt 1) {
                $hBest = [ordered]@{}
                foreach ($oF in $aFolders) {
                    $sKey = if ($oF.dfsPath) { $oF.dfsPath } else { $oF.targetPath }
                    if (-not $hBest.Contains($sKey)) {
                        $hBest[$sKey] = $oF
                    } elseif ($hBest[$sKey].state -ne 'Online' -and $oF.state -eq 'Online') {
                        $hBest[$sKey] = $oF
                    }
                }
                $aFolders = @($hBest.Values)
            }

            if ($aFolders.Count -eq 0) {
                Write-Warning "$sCallerName : $sGroupName - No folders found."
                continue
            }

            Write-Host "$sGroupName : $($aFolders.Count) folder(s) found" -ForegroundColor Cyan

            # --- Reserve summary slot ---
            $aSummary = @()
            $aMemberSectionFiles = @()
            $iSummaryTocIndex = $iTocIndex
            $iTocIndex++

            # --- Get permissions per folder ---
            $iFolderIndex = 0
            foreach ($oFolder in ($aFolders | Sort-Object folderName)) {
                $iFolderIndex++
                $iPercent = [int](($iGroupIndex - 1) / $iGroupCount * 90) + [int](($iFolderIndex / $aFolders.Count) * (90 / $iGroupCount))
                Write-Progress -Activity $sCallerName -Status "$sGroupName : $($oFolder.folderName) ($iFolderIndex/$($aFolders.Count))..." -PercentComplete $iPercent

                $aPerms = @()
                if ($oFolder.targetServer) {
                    $bExcl = $ExcludeInherited

                    if ($oFolder.dfsPath) {
                        # DFS folder: resolve via Get-DFSFolderPermissions
                        $aRawPerms = @(Get-DFSFolderPermissions -DFSFolderInfo $oFolder @hCredParam `
                            -ExcludeInherited:$bExcl)
                    } else {
                        # Filer folder: use Get-FilerFolderPermissions (localPath or UNC resolution)
                        $aRawPerms = @(Get-FilerFolderPermissions -FolderInfo $oFolder @hCredParam `
                            -ExcludeInherited:$bExcl)
                    }

                    # Keep only permission-specific columns
                    $aPerms = @($aRawPerms | ForEach-Object {
                        $sIdRef = $_.identityReference
                        $sType = if ($sIdRef) { Resolve-IdentityType $sIdRef } else { 'unknown' }

                        # Only groups go into the Groups tab
                        if ($sType -eq 'group' -and $sIdRef -and -not $hAllGroupIdentities.ContainsKey($sIdRef)) {
                            $hAllGroupIdentities[$sIdRef] = $true
                        }

                        [PSCustomObject][ordered]@{
                            identityReference = $sIdRef
                            type              = $sType
                            fileSystemRights  = $_.fileSystemRights
                            accessControlType = $_.accessControlType
                            isInherited       = $_.isInherited
                            inheritanceFlags  = $_.inheritanceFlags
                        }
                    })
                }

                # Summary row
                $hSummaryRow = [ordered]@{
                    folderName   = $oFolder.folderName
                    targetServer = $oFolder.targetServer
                    targetPath   = $oFolder.targetPath
                    source       = $oFolder.source
                    aclCount     = $aPerms.Count
                }
                if ($oFolder.dfsPath) { $hSummaryRow['dfsPath'] = $oFolder.dfsPath }
                $aSummary += [PSCustomObject]$hSummaryRow

                # Per-folder permissions section (full path as title)
                if ($aPerms.Count -gt 0) {
                    $sSectionTitle = if ($oFolder.dfsPath) { $oFolder.dfsPath } else { $oFolder.targetPath }
                    $sId = "sec_$iTocIndex"
                    $iTocIndex++
                    $aMemberSectionFiles += ConvertTo-HTMLSectionV2 -Title $sSectionTitle -Id $sId -Data $aPerms `
                        -Tab $sTab -NameProperty 'identityReference' -LinkableColumns @{ identityReference = "type=group" } -DetectAllColumns
                    $iTotal += $aPerms.Count
                }
            }

            # --- Summary section ---
            if ($aSummary.Count -gt 0) {
                # Conditional linkable columns mirror what the per-
                # folder ACL section's Title carries (data-category):
                #   - DFS rows   -> section Title is dfsPath
                #   - Filer rows -> section Title is targetPath
                # So we chip targetPath when source starts with
                # "Filer", and dfsPath when source starts with "DFS".
                # Without the per-row gating, the wrong column would
                # render as a chip that clicks nowhere.
                $sSummaryFile = ConvertTo-HTMLSectionV2 -Title $sGroupName -Id "sec_$iSummaryTocIndex" -Data $aSummary `
                    -Tab $sTab -NameProperty 'folderName' -DetectAllColumns `
                    -LinkableColumns @{
                        targetPath = "source=Filer*"
                        dfsPath    = "source=DFS*"
                    }
                $aSectionFiles += $sSummaryFile
                $iTotal += $aSummary.Count
            }
            $aSectionFiles += $aMemberSectionFiles
        }

        # ===== GROUPS TAB: resolve AD group members =====
        if ($hAllGroupIdentities.Count -gt 0) {
            $aTabs += "groups"

            Write-Progress -Activity $sCallerName -Status "Resolving AD groups ($($hAllGroupIdentities.Count))..." -PercentComplete 92

            $aGroupSummary = @()
            $aGroupSectionFiles = @()
            $iGroupSummaryTocIndex = $iTocIndex
            $iTocIndex++

            $iGrpIndex = 0
            $aGroupNames = @($hAllGroupIdentities.Keys | Sort-Object)

            foreach ($sIdentity in $aGroupNames) {
                $iGrpIndex++
                Write-Progress -Activity $sCallerName -Status "Group: $sIdentity ($iGrpIndex/$($aGroupNames.Count))..." `
                    -PercentComplete (92 + [int](($iGrpIndex / $aGroupNames.Count) * 6))

                # Extract sAMAccountName from DOMAIN\name
                $sSAM = ($sIdentity -split '\\', 2)[-1]
                $sGroupDescription = $null

                $aMembers = @()
                try {
                    # Step 1: find group(s) in GC, match by msDS-PrincipalName (NETBIOS\name)
                    $aGroupGC = @(Get-ADGroup -Identity $sSAM -UseGlobalCatalog `
                        -Properties name, objectclass, distinguishedname, description, 'msDS-PrincipalName')
                    $oGroupGC = $aGroupGC | Where-Object { $_.'msDS-PrincipalName' -ieq $sIdentity } | Select-Object -First 1
                    if (-not $oGroupGC) {
                        $oGroupGC = $aGroupGC | Where-Object { "$($_.objectclass)" -eq 'group' } | Select-Object -First 1
                    }

                    # Step 2: re-read from the group's home domain via LDAP to get member attribute
                    $oGroup = $null
                    if ($oGroupGC -and "$($oGroupGC.objectclass)" -eq 'group') {
                        $sDomainFQDN = (($oGroupGC.distinguishedname -split ',') | Where-Object { $_ -match '^DC=' } | ForEach-Object { $_ -replace '^DC=', '' }) -join '.'
                        $oGroup = Get-ADGroup -Identity $sSAM -Server $sDomainFQDN -Properties name, objectclass, member, description
                    }

                    if ($oGroup) {
                        $sGroupDescription = $oGroup.description
                        if ($oGroup.member) {
                            $aRawMembers = @(Get-GroupMembers -ADObject $oGroup -Recurse `
                                -ADObjectProperties @('name', 'objectclass', 'displayName', 'mail', 'title', 'department', 'userAccountControl', 'sAMAccountName', 'description', 'canonicalName'))

                            $aMembers = @($aRawMembers | Where-Object { $_.objectclass -ne 'group' } | ForEach-Object {
                                $bEnabled = if ($_.userAccountControl) { -not ($_.userAccountControl -band 2) } else { $null }
                                [PSCustomObject][ordered]@{
                                    name           = $_.name
                                    canonicalName  = $_.canonicalName
                                    displayName    = $_.displayName
                                    description    = $_.description
                                    email          = $_.mail
                                    title          = $_.title
                                    department     = $_.department
                                    enabled        = $bEnabled
                                    inheritedFrom  = $_.InheritedFrom
                                }
                            })
                        }
                    }
                } catch {
                    Write-Verbose "$sCallerName : Cannot resolve group '$sIdentity' - $_"
                }

                # Skip identities that are not AD groups
                if (-not $oGroup) { continue }

                $aGroupSummary += [PSCustomObject][ordered]@{
                    group       = $sIdentity
                    description = $sGroupDescription
                    memberCount = $aMembers.Count
                }

                $sId = "sec_$iTocIndex"
                $iTocIndex++
                if ($aMembers.Count -gt 0) {
                    $aGroupSectionFiles += ConvertTo-HTMLSectionV2 -Title $sIdentity -Id $sId -Data $aMembers `
                        -Tab "groups" -NameProperty 'name' -DetectAllColumns
                    $iTotal += $aMembers.Count
                } else {
                    # Empty group: placeholder section so the link has a destination
                    $aGroupSectionFiles += ConvertTo-HTMLSectionV2 -Title $sIdentity -Id $sId `
                        -Tab "groups" -EmptyMessage "This group has no members"
                }
            }

            # Groups summary
            if ($aGroupSummary.Count -gt 0) {
                $sSummaryFile = ConvertTo-HTMLSectionV2 -Title "Groups Summary" -Id "sec_$iGroupSummaryTocIndex" -Data $aGroupSummary `
                    -Tab "groups" -NameProperty 'group' -LinkableColumns @('group') -DetectAllColumns
                $aSectionFiles += $sSummaryFile
                $iTotal += $aGroupSummary.Count
            }
            $aSectionFiles += $aGroupSectionFiles
        }

        # ===== GENERATE HTML REPORT =====
        if ($aSectionFiles.Count -eq 0) {
            Write-Warning "$sCallerName : No data collected, skipping report generation."
            return
        }

        Write-Progress -Activity $sCallerName -Status "Generating HTML report..." -PercentComplete 95

        $sAccentColor = "#6a1b9a"
        $sNavColor    = "#4a148c"
        $oReport = New-HTMLReport -Title "Filer Access Export - $sTimestamp" `
            -Brand "Filer Access" `
            -DeviceInfo "DFS / File Servers" `
            -SectionFiles $aSectionFiles `
            -Tabs $aTabs `
            -AccentColor $sAccentColor `
            -NavColor $sNavColor `
            -FilePath $sFilePath `
            -ObjectCount $iTotal `
            -SidebarWidth 380

        Write-Progress -Activity $sCallerName -Completed

        Write-Host "Filer access exported: $sFilePath ($iTotal objects)" -ForegroundColor Green

        return $oReport
    }
}
