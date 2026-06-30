function Export-ADTimeReport {
    <#
    .SYNOPSIS
        Exports Active Directory time-synchronisation evidence
        into a standalone HTML report.

    .DESCRIPTION
        Enumerates every domain in the current forest (or a user-
        supplied subset), queries each domain controller's w32time
        configuration, and emits one section per domain with the
        per-DC details: NTP type, configured server, current
        source, last sync time, last sync source, offset. The PDC
        Emulator is flagged in its own column for cross-checking
        against the canonical NTP source.

        This used to be the "time" tab of a larger monolithic AD
        export. Lifted out so audit packs ship focused
        single-concern reports.

    .PARAMETER FolderPath
        Local destination folder for the HTML report. Must exist.

    .PARAMETER Server
        Optional AD server hint (passed through to discovery
        helpers).

    .PARAMETER Credential
        Optional credentials for AD queries and remote w32tm calls.

    .PARAMETER Domain
        Optional domain filter (exact names). When supplied, the
        report only covers those domains - everything else is
        skipped. Default: every domain of the current forest.

    .OUTPUTS
        [System.IO.FileInfo] - the generated HTML file.

    .EXAMPLE
        Export-ADTimeReport -FolderPath C:\Exports

    .EXAMPLE
        Export-ADTimeReport -FolderPath C:\Exports `
            -Domain 'stago.grp', 'us.am.stago.grp'

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-06-03, Loic Ade) - Initial version. Extracted
                             from the legacy Export-ADConfiguration
                             so the time-sync evidence ships as a
                             focused standalone report, decoupled
                             from the group / security / GPO
                             sections.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$FolderPath,

        [string]$Server,

        [PSCredential]$Credential,

        [string[]]$Domain
    )

    Begin {
        if (-not (Test-Path $FolderPath -PathType Container)) {
            throw "Folder does not exist: $FolderPath"
        }
    }

    Process {
        $oSW = [System.Diagnostics.Stopwatch]::StartNew()

        $sTimestamp  = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $sFilePath   = Join-Path $FolderPath "Export_AD_Time_${sTimestamp}.html"
        $sCallerName = "Exporting AD Time Synchronization"

        $iTotal        = 0
        $iTocIndex     = 0
        $aSectionFiles = @()
        $sTimeTab      = 'Time'
        $aTabs         = @($sTimeTab)

        # --- Forest enumeration --------------------------------------
        Write-Progress -Activity $sCallerName -Status "Enumerating forest domains..." -PercentComplete 5
        $aDomains = @(Get-CurrentADForestDomains)
        if ($Domain) {
            $aDomains = @($aDomains | Where-Object { $_.Name -in $Domain })
        }
        if ($aDomains.Count -eq 0) {
            Write-Warning "$sCallerName : no domain matched - aborting."
            return
        }
        Write-Host "Forest enumeration : $($aDomains.Count) domain(s)" -ForegroundColor Cyan

        # Hierarchical context list (parents before children) for
        # the sidebar domain filter. Same layout as the legacy AD
        # export so the report's sidebar behaves identically.
        $hDomainParent = @{}
        foreach ($oDom in $aDomains) {
            $hDomainParent[$oDom.Name] = if ($oDom.Parent) { $oDom.Parent.Name } else { '' }
        }
        $fnGetDepth = {
            Param([string]$Name)
            $d = 0; $s = $Name
            while ($hDomainParent[$s]) { $d++; $s = $hDomainParent[$s] }
            return $d
        }
        $fnHierarchical = {
            Param([array]$Items, [string]$ParentName = '')
            $aResult   = @()
            $aChildren = @($Items | Where-Object { $_.parent -eq $ParentName } | Sort-Object { $_.name })
            foreach ($oChild in $aChildren) {
                $aResult += @{ name = $oChild.name; depth = $oChild.depth }
                $aResult += & $fnHierarchical $Items $oChild.name
            }
            return $aResult
        }
        $aDomainsWithDepth = @($aDomains | ForEach-Object {
            @{ name = $_.Name; depth = (& $fnGetDepth $_.Name); parent = $hDomainParent[$_.Name] }
        })
        $aDomainContexts = @(& $fnHierarchical $aDomainsWithDepth)

        # --- Per-domain time configuration ---------------------------
        $iDomCount = $aDomains.Count
        $iDomIdx   = 0
        foreach ($oDomain in $aDomains) {
            $iDomIdx++
            $sDomainName = $oDomain.Name
            $iPctStart   = [int](10 + 80 * (($iDomIdx - 1) / $iDomCount))
            $iPctEnd     = [int](10 + 80 *  ($iDomIdx      / $iDomCount))
            Write-Progress -Activity $sCallerName -Status "$sDomainName - Time Synchronization..." -PercentComplete $iPctStart

            try {
                $aDCs = @(Get-ADDomainControllers -Domain $sDomainName)
                if ($aDCs.Count -eq 0) {
                    Write-Warning "$sCallerName : $sDomainName - No domain controllers found."
                    continue
                }
                $sPDCName = $oDomain.PdcRoleOwner.Name

                $aTimeData = @()
                $iDCIdx = 0
                foreach ($oDC in $aDCs) {
                    $iDCIdx++
                    $sDCName = $oDC.Name
                    $iPct = [int]($iPctStart + ($iPctEnd - $iPctStart) * ($iDCIdx / $aDCs.Count))
                    Write-Progress -Activity $sCallerName -Status "$sDomainName - $sDCName..." -PercentComplete $iPct

                    try {
                        $hW32Params = @{ ComputerName = $sDCName }
                        if ($Credential) { $hW32Params['Credential'] = $Credential }
                        $oTimeConfig = Get-W32TimeConfiguration @hW32Params
                        $aTimeData += [PSCustomObject][ordered]@{
                            computerName   = $sDCName
                            isPDCEmulator  = ($sDCName -eq $sPDCName)
                            type           = $oTimeConfig.Type
                            ntpServer      = $oTimeConfig.NtpServer
                            currentSource  = $oTimeConfig.CurrentSource
                            lastSyncTime   = $oTimeConfig.LastSyncTime
                            lastSyncSource = $oTimeConfig.LastSyncSource
                            offset         = $oTimeConfig.Offset
                        }
                    } catch {
                        Write-Warning "$sCallerName : $sDomainName / $sDCName / Time - $_"
                        $aTimeData += [PSCustomObject][ordered]@{
                            computerName   = $sDCName
                            isPDCEmulator  = ($sDCName -eq $sPDCName)
                            type           = $null
                            ntpServer      = $null
                            currentSource  = $null
                            lastSyncTime   = $null
                            lastSyncSource = $null
                            offset         = "Error: $_"
                        }
                    }
                }

                $sId = "sec_$iTocIndex"; $iTocIndex++
                $aSectionFiles += ConvertTo-HTMLSectionV2 -Title "Time Synchronization" -Id $sId `
                    -Data $aTimeData -Tab $sTimeTab -Context $sDomainName `
                    -NameProperty 'computerName' -DetectAllColumns
                $iTotal += $aTimeData.Count
                Write-Host "$sDomainName : $($aDCs.Count) DC(s) time configuration collected" -ForegroundColor Cyan
            } catch {
                Write-Warning "$sCallerName : $sDomainName / Time Synchronization - $_"
            }
        }

        if ($aSectionFiles.Count -eq 0) {
            Write-Warning "$sCallerName : No data collected, skipping report generation."
            return
        }

        Write-Progress -Activity $sCallerName -Status "Generating HTML report..." -PercentComplete 95

        $hContexts      = @{ $sTimeTab = $aDomainContexts }
        $hContextLabels = @{ $sTimeTab = 'Domain' }

        $oSW.Stop()
        $oReport = New-HTMLReport -Title "AD Time Synchronization - $sTimestamp" `
            -Brand "AD Time" `
            -DeviceInfo "Active Directory" `
            -SectionFiles $aSectionFiles `
            -Tabs $aTabs `
            -Contexts $hContexts `
            -ContextLabels $hContextLabels `
            -AccentColor "#1565c0" `
            -FilePath $sFilePath `
            -ObjectCount $iTotal `
            -GenerationDuration $oSW.Elapsed

        Write-Progress -Activity $sCallerName -Completed
        Write-Host "AD time synchronization exported: $sFilePath ($iTotal DC(s))" -ForegroundColor Green
        return $oReport
    }
}
