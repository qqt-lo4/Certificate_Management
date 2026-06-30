function Test-TLSCipherSuite_SSLLabs {
    <#
    .SYNOPSIS
        Backend for Test-TLSCipherSuite: queries the public Qualys
        SSL Labs API (vantage point on the Internet) and parses its
        async-completed JSON into the unified TLS-result shape.

    .DESCRIPTION
        Invoked via the Test-TLSCipherSuite dispatcher when
        -Source SSLLabs is requested. The API is fully async:
            GET /analyze?host=X&startNew=on&publish=off
            (status moves IN_PROGRESS -> READY over ~1-2 minutes)
            GET /analyze?host=X&all=done
            (final payload once status == READY)

        Notable query params we set:
            startNew=on    : force a fresh scan, not a cached result
                             (use $false to reuse the platform cache
                              and stay under the quota)
            publish=off    : do NOT publish the result on ssllabs.com.
                             Crucial for confidential audits.
            all=done       : return the full details only when ready.
            ignoreMismatch=on : continue even if the cert CN doesn't
                                match the requested host.

        The public tier is rate-limited to roughly 25 scans / 24h /
        source IP and 3 concurrent scans. The function polls every
        $PollIntervalSeconds (default 10) up to $MaxPollMinutes
        (default 5) before giving up with a ScanError.

    .PARAMETER ComputerName
        Public FQDN (the SSL Labs scanners must be able to reach it
        from the Internet).

    .PARAMETER Port
        TCP port. Default 443. Surfaced on the output for
        consistency with the other backends; note that the SSL Labs
        API actually probes 443 only.

    .PARAMETER UseCache
        When set, allows the API to return a cached result (if any)
        instead of forcing a fresh scan. Saves quota.

    .PARAMETER PollIntervalSeconds
        Seconds between two polling calls while the scan is running.
        Default 10.

    .PARAMETER MaxPollMinutes
        Max time to wait before giving up. Default 5.

    .OUTPUTS
        Unified TLS-result PSCustomObject (see Test-TLSCipherSuite).

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [int]$Port = 443,

        [switch]$UseCache,

        [int]$PollIntervalSeconds = 10,

        [int]$MaxPollMinutes = 5
    )
    Process {
        $sBaseUrl = 'https://api.ssllabs.com/api/v3/analyze'
        $sStartUrl = "$sBaseUrl`?host=$([uri]::EscapeDataString($ComputerName))&publish=off&ignoreMismatch=on&all=done"
        if (-not $UseCache) { $sStartUrl += '&startNew=on' } else { $sStartUrl += '&fromCache=on' }

        function New-Result {
            Param([string]$Err, $Raw = $null)
            [PSCustomObject]@{
                Host            = $ComputerName
                Port            = $Port
                Source          = 'SSLLabs'
                ScanDate        = Get-Date
                Grade           = $null
                LeastStrength   = $null
                Protocols       = $null
                CipherSuites    = @()
                Certificate     = $null
                Vulnerabilities = $null
                ScanError       = $Err
                RawResponse     = $Raw
            }
        }

        # --- Kick off the scan ---------------------------------------------
        $sProgressActivity = "SSL Labs scan: $ComputerName"
        Write-Progress -Activity $sProgressActivity -Status "Starting scan..." -PercentComplete 0
        $oResp = $null
        try {
            $oResp = Invoke-RestMethod -Uri $sStartUrl -Method GET -ErrorAction Stop
        } catch {
            Write-Progress -Activity $sProgressActivity -Completed
            return (New-Result -Err "SSLLabs start failed: $($_.Exception.Message)")
        }

        # --- Poll until READY / ERROR / timeout ----------------------------
        # SSL Labs reports progress per endpoint (0..100) and an
        # "eta" in seconds. We surface the average across endpoints
        # in a Write-Progress so the user sees the scan moving forward
        # instead of staring at a silent prompt for 1-2 minutes.
        $dtDeadline = (Get-Date).AddMinutes($MaxPollMinutes)
        $sPollUrl = "$sBaseUrl`?host=$([uri]::EscapeDataString($ComputerName))&publish=off&all=done"
        while ($oResp.status -ne 'READY' -and $oResp.status -ne 'ERROR') {
            if ((Get-Date) -gt $dtDeadline) {
                Write-Progress -Activity $sProgressActivity -Completed
                return (New-Result -Err "SSLLabs polling timed out after $MaxPollMinutes minute(s) - last status: $($oResp.status)" -Raw $oResp)
            }

            # Compute aggregate progress from endpoints (when present).
            # During DNS / pre-scan phase no endpoints exist yet - we
            # report 0% and the platform status message.
            $iPct = 0
            $sEta = ''
            $aEps = @($oResp.endpoints)
            if ($aEps.Count -gt 0) {
                $iSum = 0; $iCnt = 0; $iEtaMax = -1
                foreach ($oEp in $aEps) {
                    if ($null -ne $oEp.progress) {
                        $iSum += [int]$oEp.progress
                        $iCnt++
                    }
                    if ($null -ne $oEp.eta -and [int]$oEp.eta -gt $iEtaMax) {
                        $iEtaMax = [int]$oEp.eta
                    }
                }
                if ($iCnt -gt 0) { $iPct = [int]($iSum / $iCnt) }
                if ($iEtaMax -gt 0) { $sEta = " - ETA ~${iEtaMax}s" }
            }
            $sMsg = if ($oResp.endpoints -and $oResp.endpoints[0].statusMessage) {
                "$($oResp.status) ($($oResp.endpoints[0].statusMessage))$sEta"
            } else {
                "$($oResp.status)$sEta"
            }
            Write-Progress -Activity $sProgressActivity -Status $sMsg -PercentComplete $iPct

            Start-Sleep -Seconds $PollIntervalSeconds
            try {
                $oResp = Invoke-RestMethod -Uri $sPollUrl -Method GET -ErrorAction Stop
            } catch {
                Write-Progress -Activity $sProgressActivity -Completed
                return (New-Result -Err "SSLLabs poll failed: $($_.Exception.Message)" -Raw $oResp)
            }
        }

        Write-Progress -Activity $sProgressActivity -Completed

        if ($oResp.status -eq 'ERROR') {
            return (New-Result -Err "SSLLabs returned status ERROR: $($oResp.statusMessage)" -Raw $oResp)
        }

        # --- Project the first endpoint's payload into our shape -----------
        # An SSL Labs scan can return multiple endpoints (one per IP
        # behind the FQDN). We project the first one and surface the
        # rest in RawResponse for the curious. For load-balanced
        # multi-IP hosts the report can iterate over endpoints later.
        $aEndpoints = @($oResp.endpoints)
        if ($aEndpoints.Count -eq 0) {
            return (New-Result -Err "SSLLabs READY but returned 0 endpoints" -Raw $oResp)
        }
        $oEp = $aEndpoints[0]
        if (-not $oEp.details) {
            return (New-Result -Err "SSLLabs endpoint has no .details (statusMessage: $($oEp.statusMessage))" -Raw $oResp)
        }
        $oD = $oEp.details

        # Protocols: SSL Labs returns a sparse list - keep only the
        # ones the platform advertises (the unified shape below pre-
        # fills the known set so empty == not supported).
        $hProtocols = [ordered]@{
            'SSLv3'   = $false
            'TLSv1.0' = $false
            'TLSv1.1' = $false
            'TLSv1.2' = $false
            'TLSv1.3' = $false
        }
        foreach ($oP in @($oD.protocols)) {
            $sKey = "$($oP.name)v$($oP.version)"
            # SSL Labs reports the protocol name as "TLS" and the
            # version as "1.0" / "1.1" / "1.2" / "1.3". Adjust SSLv3
            # which carries name="SSL" version="3.0".
            if ($oP.name -eq 'SSL' -and $oP.version -eq '3.0') { $sKey = 'SSLv3' }
            if ($hProtocols.Contains($sKey)) { $hProtocols[$sKey] = $true }
        }

        # Cipher suites: array of { protocol, list }. Protocol id maps
        # to the protocols above via id (771 = TLS1.2, 772 = TLS1.3, ...).
        # Build a quick id->name lookup so each cipher row carries the
        # readable protocol name.
        $hProtoIdToName = @{}
        foreach ($oP in @($oD.protocols)) {
            $sKey = "$($oP.name)v$($oP.version)"
            if ($oP.name -eq 'SSL' -and $oP.version -eq '3.0') { $sKey = 'SSLv3' }
            $hProtoIdToName[[int]$oP.id] = $sKey
        }
        $aCiphers = @()
        foreach ($oSuite in @($oD.suites)) {
            $sProtoName = $hProtoIdToName[[int]$oSuite.protocol]
            foreach ($oC in @($oSuite.list)) {
                # SSL Labs "q" field: 0=insecure, 1=weak, 2=moderate,
                # 3=secure, 4=excellent (the doc varies). We surface
                # it raw and let the report formatter map it.
                $sQual = switch ([int]$oC.q) {
                    0 { 'INSECURE' }
                    1 { 'WEAK' }
                    2 { 'MODERATE' }
                    default { 'SECURE' }
                }
                $aCiphers += [PSCustomObject]@{
                    Protocol = $sProtoName
                    Name     = [string]$oC.name
                    Strength = [int]$oC.cipherStrength
                    Quality  = $sQual
                    KexInfo  = if ($oC.kxType) { "$($oC.kxType) $($oC.kxStrength)bits" } else { $null }
                }
            }
        }

        # Certificate: SSL Labs returns details.certChains[0].certIds[0]
        # or details.cert. We try the leaf cert path.
        $oCert = $null
        $oLeafCert = $null
        if ($oD.certChains -and $oD.certChains.Count -gt 0 -and $oResp.certs) {
            $sLeafId = $oD.certChains[0].certIds[0]
            $oLeafCert = @($oResp.certs | Where-Object { $_.id -eq $sLeafId })[0]
        }
        if (-not $oLeafCert -and $oD.cert) { $oLeafCert = $oD.cert }
        if ($oLeafCert) {
            $oCert = [PSCustomObject]@{
                Subject  = [string]$oLeafCert.subject
                Issuer   = if ($oLeafCert.issuerSubject) { [string]$oLeafCert.issuerSubject } else { [string]$oLeafCert.issuerLabel }
                NotAfter = if ($oLeafCert.notAfter) { [System.DateTimeOffset]::FromUnixTimeMilliseconds([int64]$oLeafCert.notAfter).UtcDateTime } else { $null }
                KeyAlgo  = [string]$oLeafCert.keyAlg
                KeyBits  = [int]$oLeafCert.keySize
            }
        }

        # Vulnerabilities. SSL Labs surfaces these as named flags.
        # Booleans are direct. Ints use the documented scale
        # 0=unknown, 1=not vulnerable, 2=possibly vulnerable,
        # 3=vulnerable: we flag True at >= 2.
        # Insecure renegotiation comes from renegSupport (bit field):
        # bit 0 set = supports insecure client-initiated renegotiation.
        $hVulns = [ordered]@{
            Heartbleed       = [bool]$oD.heartbleed
            POODLE_SSLv3     = [bool]$oD.poodle
            POODLE_TLS       = ([int]$oD.poodleTls -ge 2)
            FREAK            = [bool]$oD.freak
            Logjam           = [bool]$oD.logjam
            DROWN            = [bool]$oD.drownVulnerable
            OpenSSL_CCS      = ([int]$oD.openSslCcs -ge 2)
            OpenSSL_Lucky20  = ([int]$oD.openSSLLuckyMinus20 -ge 2)
            RC4_Support      = [bool]$oD.supportsRc4
            Insecure_Renegot = ($null -ne $oD.renegSupport) -and (([int]$oD.renegSupport -band 1) -ne 0)
        }

        return [PSCustomObject]@{
            Host            = $ComputerName
            Port            = $Port
            Source          = 'SSLLabs'
            ScanDate        = Get-Date
            Grade           = [string]$oEp.grade
            LeastStrength   = $null
            Protocols       = $hProtocols
            CipherSuites    = $aCiphers
            Certificate     = $oCert
            Vulnerabilities = $hVulns
            ScanError       = $null
            RawResponse     = $oResp
        }
    }
}
