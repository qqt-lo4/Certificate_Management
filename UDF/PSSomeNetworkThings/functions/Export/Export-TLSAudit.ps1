function Export-TLSAudit {
    <#
    .SYNOPSIS
        Exports a TLS configuration audit (protocols, cipher suites,
        certificate, known vulnerabilities) for a list of targets,
        each scanned with the source declared on the entry.

    .DESCRIPTION
        Iterates a list of @{ Host; Port; Source } target rows,
        invokes Test-TLSCipherSuite per target with the declared
        backend, and renders an HTML report with:

          - A summary table (one row per target) with overall grade
            or weakest cipher strength, count of enabled protocols
            and cipher suites, and the scan error if any. Clicking a
            row's host scrolls to that host's per-section block.
          - Per host:
              * Protocols Supported   (small table)
              * Certificate           (key/value table)
              * Known Vulnerabilities (table, when the source checks
                them - SSL Labs does, Nmap does not)
              * Cipher Suites         (larger table, sorted by
                protocol then quality)

        Generic helper - no project-specific dependencies. The
        orchestrator decides which targets land here from its own
        config.

    .PARAMETER FolderPath
        Local destination folder for the HTML report. Must exist.

    .PARAMETER Target
        Array of target descriptors. Each entry is a hashtable /
        PSCustomObject with keys:
            Host   (mandatory)
            Port   (optional, default 443)
            Source (mandatory, currently Nmap | SSLLabs)
        Example:
            @(
                @{ Host='frpscm01.stago.grp'; Port=443; Source='Nmap'    },
                @{ Host='pam-eu.stago.com';   Port=443; Source='SSLLabs' }
            )

    .PARAMETER UseCache
        Forwarded to SSLLabs backend (return cached result if any,
        saves quota). Ignored on Nmap.

    .OUTPUTS
        [System.IO.FileInfo] - the generated HTML file.

    .EXAMPLE
        $aTargets = @(
            @{ Host='frpscm01.stago.grp'; Source='Nmap'    },
            @{ Host='www.stago.com';      Source='SSLLabs' }
        )
        Export-TLSAudit -FolderPath C:\Exports -Target $aTargets

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-06-23, Loic Ade) - Initial version. Drives
                             Test-TLSCipherSuite per target,
                             unified summary + per-host detail
                             sections.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$FolderPath,

        [Parameter(Mandatory)]
        [object[]]$Target,

        [switch]$UseCache
    )

    Begin {
        if (-not (Test-Path $FolderPath -PathType Container)) {
            throw "Folder does not exist: $FolderPath"
        }
    }

    Process {
        $oSW = [System.Diagnostics.Stopwatch]::StartNew()
        $sTimestamp  = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $sFilePath   = Join-Path $FolderPath "Export_TLS_Audit_${sTimestamp}.html"
        $sCallerName = "Exporting TLS Audit"

        $iTotal        = 0
        $iTocIndex     = 0
        $aSectionFiles = @()
        $sSummaryTab   = 'Summary'
        $aTabs         = @($sSummaryTab)

        # --- Run scans ------------------------------------------------------
        # Nmap targets are batched (one nmap call per port group) so
        # the requireAdministrator manifest of the Windows nmap.exe
        # only fires UAC once for the whole report - not once per
        # site. SSLLabs targets stay one-by-one since each kicks off
        # an async API call with its own polling loop.
        $aValid = @()
        foreach ($oT in $Target) {
            $sHost = [string]$oT.Host
            if (-not $sHost) {
                Write-Warning "$sCallerName : target entry missing Host - skipped."
                continue
            }
            $sSource = [string]$oT.Source
            if (-not $sSource) {
                Write-Warning "$sCallerName : target '$sHost' missing Source - skipped."
                continue
            }
            $aValid += [PSCustomObject]@{
                Host   = $sHost
                Port   = if ($oT.Port) { [int]$oT.Port } else { 443 }
                Source = $sSource
            }
        }

        $aResults = @()

        # Group Nmap targets by port - one batched nmap call per
        # group so each port-set fires UAC at most once.
        $aNmapGroups = @($aValid | Where-Object { $_.Source -eq 'Nmap' } | Group-Object Port)
        $iNmapGroupIdx = 0
        foreach ($oGroup in $aNmapGroups) {
            $iNmapGroupIdx++
            $iPort  = [int]$oGroup.Name
            $aHosts = @($oGroup.Group | ForEach-Object { $_.Host })
            Write-Progress -Activity $sCallerName -Status "Nmap batch port ${iPort}: $($aHosts -join ', ')..." `
                -PercentComplete ([int](($iNmapGroupIdx - 1) / [Math]::Max($aNmapGroups.Count + 1, 1) * 90))
            try {
                $aResults += @(Test-TLSCipherSuite_Nmap -ComputerName $aHosts -Port $iPort)
            } catch {
                Write-Warning "$sCallerName : Nmap batch port $iPort - $($_.Exception.Message)"
            }
        }

        # SSLLabs targets - one async call per host. The backend's
        # own Write-Progress reports polling progress.
        $aSSLLabs = @($aValid | Where-Object { $_.Source -eq 'SSLLabs' })
        $iSslIdx = 0
        foreach ($oT in $aSSLLabs) {
            $iSslIdx++
            Write-Progress -Activity $sCallerName -Status "SSLLabs $($oT.Host) ($iSslIdx/$($aSSLLabs.Count))..." `
                -PercentComplete (50 + [int]($iSslIdx / [Math]::Max($aSSLLabs.Count, 1) * 40))
            $hScanParams = @{ ComputerName = $oT.Host; Port = $oT.Port; Source = 'SSLLabs' }
            if ($UseCache) { $hScanParams['UseCache'] = $true }
            try {
                $aResults += @(Test-TLSCipherSuite @hScanParams)
            } catch {
                Write-Warning "$sCallerName : '$($oT.Host)' via SSLLabs - $($_.Exception.Message)"
            }
        }

        if ($aResults.Count -eq 0) {
            Write-Warning "$sCallerName : no scan results collected - skipping report generation."
            return
        }

        # --- Summary --------------------------------------------------------
        $aSummary = @($aResults | ForEach-Object {
            $aProtoEnabled = @()
            if ($_.Protocols) {
                foreach ($sP in $_.Protocols.Keys) {
                    if ($_.Protocols[$sP]) { $aProtoEnabled += $sP }
                }
            }
            [PSCustomObject][ordered]@{
                host           = [string]$_.Host
                port           = [int]$_.Port
                source         = [string]$_.Source
                scanDate       = [string]$_.ScanDate
                grade          = [string]$_.Grade
                leastStrength  = [string]$_.LeastStrength
                enabledProtos  = ($aProtoEnabled -join ', ')
                cipherCount    = @($_.CipherSuites).Count
                scanError      = [string]$_.ScanError
            }
        })

        $sId = "sec_$iTocIndex"; $iTocIndex++
        $aSectionFiles += ConvertTo-HTMLSectionV2 -Title "TLS Audit Summary" -Id $sId `
            -Data $aSummary -Tab $sSummaryTab -NameProperty 'host' -DetectAllColumns `
            -LinkableColumns @('host')
        $iTotal += $aSummary.Count

        # --- Per-host tabs --------------------------------------------------
        # One tab per host. The FIRST section in each host tab carries
        # the host name as its Title - that's the navigation target
        # the summary's host chip resolves to (obj-link findSection
        # matches by data-category = section title, and the renderer
        # switches to that section's tab on click). The protocol table
        # rides inside this first section. The 3 follow-up sections
        # (Certificate, Vulnerabilities, Cipher Suites) use generic
        # titles since the tab already disambiguates the host.
        foreach ($oR in $aResults) {
            $sHost = [string]$oR.Host

            # Skip per-host details when the scan failed - the summary
            # row already exposes the scanError; building empty detail
            # sections would just be noise.
            if ($oR.ScanError) { continue }

            $sHostTab = $sHost
            if ($sHostTab -notin $aTabs) { $aTabs += $sHostTab }

            # First section = anchor + Protocols Supported.
            if ($oR.Protocols) {
                $aRows = @($oR.Protocols.GetEnumerator() | ForEach-Object {
                    [PSCustomObject][ordered]@{
                        protocol = [string]$_.Key
                        enabled  = [bool]$_.Value
                    }
                })
                $sId = "sec_$iTocIndex"; $iTocIndex++
                $aSectionFiles += ConvertTo-HTMLSectionV2 -Title $sHost -Id $sId `
                    -Data $aRows -Tab $sHostTab -NameProperty 'protocol' `
                    -DetectAllColumns -NoSort `
                    -DisabledFlagProperty 'enabled'
                $iTotal += $aRows.Count
            }

            # Certificate.
            if ($oR.Certificate) {
                $oC = $oR.Certificate
                $aRows = @([PSCustomObject][ordered]@{
                    field    = 'subject'
                    value    = [string]$oC.Subject
                },
                [PSCustomObject][ordered]@{
                    field    = 'issuer'
                    value    = [string]$oC.Issuer
                },
                [PSCustomObject][ordered]@{
                    field    = 'notAfter'
                    value    = [string]$oC.NotAfter
                },
                [PSCustomObject][ordered]@{
                    field    = 'keyAlgo'
                    value    = [string]$oC.KeyAlgo
                },
                [PSCustomObject][ordered]@{
                    field    = 'keyBits'
                    value    = if ($oC.KeyBits) { [string]$oC.KeyBits } else { '' }
                })
                $sId = "sec_$iTocIndex"; $iTocIndex++
                $aSectionFiles += ConvertTo-HTMLSectionV2 -Title "Certificate" -Id $sId `
                    -Data $aRows -Tab $sHostTab -NameProperty 'field' `
                    -DetectAllColumns -NoSort
                $iTotal += $aRows.Count
            }

            # Vulnerabilities - only when source surfaces them.
            if ($oR.Vulnerabilities) {
                $aRows = @($oR.Vulnerabilities.GetEnumerator() | ForEach-Object {
                    [PSCustomObject][ordered]@{
                        check    = [string]$_.Key
                        # disabledFlag prop: True means "safe" (NOT
                        # vulnerable). We invert the value so a vuln
                        # row stays bright while a safe row is grayed.
                        notVuln  = -not [bool]$_.Value
                        verdict  = if ([bool]$_.Value) { 'VULNERABLE' } else { 'ok' }
                    }
                })
                $sId = "sec_$iTocIndex"; $iTocIndex++
                $aSectionFiles += ConvertTo-HTMLSectionV2 -Title "Known Vulnerabilities" -Id $sId `
                    -Data $aRows -Tab $sHostTab -NameProperty 'check' `
                    -DetectAllColumns -NoSort `
                    -DisabledFlagProperty 'notVuln' `
                    -HiddenCols @('notVuln') `
                    -RowFilters @(
                        @{ Label = 'Hide non-vulnerable checks'; HideFlag = 'd'; Default = $true }
                    )
                $iTotal += $aRows.Count
            }

            # Cipher Suites - larger table; sorted by protocol then
            # quality + name so the strongest cipher per protocol
            # sits on top.
            if ($oR.CipherSuites -and @($oR.CipherSuites).Count -gt 0) {
                $aRows = @($oR.CipherSuites | Sort-Object Protocol, Quality, Name)
                $sId = "sec_$iTocIndex"; $iTocIndex++
                $aSectionFiles += ConvertTo-HTMLSectionV2 -Title "Cipher Suites" -Id $sId `
                    -Data $aRows -Tab $sHostTab -NameProperty 'Name' `
                    -DetectAllColumns -NoSort
                $iTotal += $aRows.Count
            }
        }

        # --- Generate HTML --------------------------------------------------
        Write-Progress -Activity $sCallerName -Status "Generating HTML report..." -PercentComplete 95
        $oSW.Stop()

        $oReport = New-HTMLReport -Title "TLS Audit - $sTimestamp" `
            -Brand "TLS Audit" `
            -DeviceInfo "TLS Configuration" `
            -SectionFiles $aSectionFiles `
            -Tabs $aTabs `
            -AccentColor "#d84315" `
            -NavColor "#bf360c" `
            -FilePath $sFilePath `
            -ObjectCount $iTotal `
            -GenerationDuration $oSW.Elapsed

        Write-Progress -Activity $sCallerName -Completed
        Write-Host "TLS Audit exported: $sFilePath ($iTotal row(s), $($aResults.Count) host(s))" -ForegroundColor Green
        return $oReport
    }
}
