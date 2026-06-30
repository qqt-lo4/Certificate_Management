function Test-TLSCipherSuite_Nmap {
    <#
    .SYNOPSIS
        Backend for Test-TLSCipherSuite: runs the local nmap binary
        with the ssl-enum-ciphers script and parses its XML output
        into the unified TLS-result shape.

    .DESCRIPTION
        Invoked via the Test-TLSCipherSuite dispatcher when
        -Source Nmap is requested. Expects nmap to be discoverable
        on the host: PATH first, then the two standard install
        locations (Program Files / Program Files (x86)). Fails
        with a clear error when nmap is not found.

        The ssl-enum-ciphers script emits one <table> per
        protocol (TLSv1.0, TLSv1.1, TLSv1.2, TLSv1.3, SSLv3, ...).
        Each protocol carries a "ciphers" sub-table listing every
        cipher accepted by the server, with the script's letter
        strength (A / B / C / D / E / F). A bottom-line
        "least strength" element across the host is also emitted -
        we surface it as LeastStrength.

        The certificate is fetched alongside via the
        ssl-cert script (default port script). Vulnerability
        checks are NOT done by ssl-enum-ciphers - that's an SSL
        Labs differentiator.

    .PARAMETER ComputerName
        Target hostname or IP.

    .PARAMETER Port
        TCP port. Default 443.

    .OUTPUTS
        Unified TLS-result PSCustomObject (see Test-TLSCipherSuite).

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0
    #>
    [CmdletBinding()]
    Param(
        # Single host or batch list. Batching is the recommended
        # mode when scanning several targets in a row: nmap.exe on
        # Windows is often installed with the requireAdministrator
        # manifest, which fires a UAC prompt per invocation. One
        # call with N hosts = one UAC prompt + emits N results.
        [Parameter(Mandatory)]
        [string[]]$ComputerName,

        [int]$Port = 443
    )
    Process {
        # --- nmap discovery -------------------------------------------------
        $sNmap = $null
        $oCmd = Get-Command nmap -ErrorAction SilentlyContinue
        if ($oCmd) {
            $sNmap = $oCmd.Source
        } else {
            foreach ($sCandidate in @(
                "${env:ProgramFiles}\Nmap\nmap.exe",
                "${env:ProgramFiles(x86)}\Nmap\nmap.exe"
            )) {
                if ($sCandidate -and (Test-Path $sCandidate -PathType Leaf)) {
                    $sNmap = $sCandidate; break
                }
            }
        }
        # Helper: build a result PSCustomObject for one host. Used
        # both for error short-circuits (emit N error rows when nmap
        # cannot run at all) and for the per-host success path.
        function New-NmapResult {
            Param(
                [string]$ResHost,
                [int]$ResPort,
                [string]$Err,
                $Raw,
                $LeastStrength,
                $Protocols,
                $CipherSuites,
                $Cert
            )
            [PSCustomObject]@{
                Host            = $ResHost
                Port            = $ResPort
                Source          = 'Nmap'
                ScanDate        = Get-Date
                Grade           = $null
                LeastStrength   = $LeastStrength
                Protocols       = $Protocols
                CipherSuites    = if ($CipherSuites) { $CipherSuites } else { @() }
                Certificate     = $Cert
                Vulnerabilities = $null
                ScanError       = $Err
                RawResponse     = $Raw
            }
        }

        if (-not $sNmap) {
            foreach ($sH in $ComputerName) {
                New-NmapResult -ResHost $sH -ResPort $Port -Err "nmap binary not found (PATH + ProgramFiles\Nmap probed)"
            }
            return
        }

        # --- Run nmap (batched) --------------------------------------------
        # -sT forces TCP Connect scan (regular connect() syscall),
        # which does not need raw sockets and therefore works as a
        # non-admin user on Windows. Without -sT the default falls
        # to SYN scan, which on Windows requires elevation + Npcap;
        # otherwise nmap exits with "dnet: Failed to open device
        # eth0" before even reaching the port.
        # -Pn skips host discovery (the target may filter ICMP).
        # --script "ssl-enum-ciphers,ssl-cert" gets both the cipher
        # enumeration and the certificate.
        # -oX - streams the XML report to stdout.
        # $ComputerName is a string[] - PowerShell expands each
        # element as a separate positional arg to the exe, so nmap
        # receives `host1 host2 host3 ...` in a single invocation.
        # One UAC prompt for the whole batch when the binary is
        # manifested as requireAdministrator.
        $sXml = ''
        try {
            $sXml = & $sNmap -sT -Pn -p $Port --script "ssl-enum-ciphers,ssl-cert" -oX - $ComputerName 2>$null | Out-String
        } catch {
            foreach ($sH in $ComputerName) {
                New-NmapResult -ResHost $sH -ResPort $Port -Err "nmap invocation failed: $($_.Exception.Message)" -Raw $sXml
            }
            return
        }

        if (-not $sXml -or $sXml -notmatch '<nmaprun') {
            foreach ($sH in $ComputerName) {
                New-NmapResult -ResHost $sH -ResPort $Port -Err "nmap returned no XML payload" -Raw $sXml
            }
            return
        }

        $oXml = $null
        try { $oXml = [xml]$sXml } catch {
            foreach ($sH in $ComputerName) {
                New-NmapResult -ResHost $sH -ResPort $Port -Err "nmap XML parse failed: $($_.Exception.Message)" -Raw $sXml
            }
            return
        }

        # nmap-level error short-circuit (raw socket denied, name
        # resolution failure, etc.) - propagates to every requested
        # host since none could be scanned.
        $oFinished = $oXml.nmaprun.runstats.finished
        if ($oFinished -and $oFinished.exit -eq 'error') {
            foreach ($sH in $ComputerName) {
                New-NmapResult -ResHost $sH -ResPort $Port -Err "nmap exited in error: $([string]$oFinished.errormsg)" -Raw $sXml
            }
            return
        }

        # --- Iterate <host> elements ---------------------------------------
        # Map each XML host back to the user-supplied name via the
        # <hostname type="user"> element. Track which inputs got a
        # result so we can emit "not seen" errors for the rest at
        # the end (rare but happens if nmap drops a host pre-scan).
        $hHostsSeen = @{}
        $aXmlHosts  = @($oXml.nmaprun.host)
        foreach ($oXmlHost in $aXmlHosts) {
            if (-not $oXmlHost) { continue }

            $sUserName = $null
            foreach ($oHN in @($oXmlHost.hostnames.hostname)) {
                if ($oHN.type -eq 'user') { $sUserName = [string]$oHN.name; break }
            }
            if (-not $sUserName) {
                $sUserName = [string]$oXmlHost.address.addr
            }
            $hHostsSeen[$sUserName.ToLower()] = $true

            # Find the matching <port> element for the requested port.
            $oPort = $null
            foreach ($oP in @($oXmlHost.ports.port)) {
                if ([int]$oP.portid -eq $Port) { $oPort = $oP; break }
            }
            if (-not $oPort) {
                New-NmapResult -ResHost $sUserName -ResPort $Port -Err "nmap could not reach the port (no <port> element for $Port)" -Raw $sXml
                continue
            }

            $hProtocols = [ordered]@{
                'SSLv3'   = $false
                'TLSv1.0' = $false
                'TLSv1.1' = $false
                'TLSv1.2' = $false
                'TLSv1.3' = $false
            }
            $aCiphers = @()
            $sLeastStrength = $null
            $oCert = $null

            foreach ($oScript in @($oPort.script)) {
                if (-not $oScript) { continue }
                switch ($oScript.id) {
                    'ssl-enum-ciphers' {
                        foreach ($oTable in @($oScript.table)) {
                            if (-not $oTable.key) { continue }
                            $sProto = $oTable.key
                            if ($hProtocols.Contains($sProto)) { $hProtocols[$sProto] = $true }

                            $oCipherTable = @($oTable.table | Where-Object { $_.key -eq 'ciphers' })
                            if ($oCipherTable) {
                                foreach ($oCipher in @($oCipherTable[0].table)) {
                                    $hElems = @{}
                                    foreach ($oEl in @($oCipher.elem)) {
                                        if ($null -ne $oEl.key) { $hElems[$oEl.key] = $oEl.'#text' }
                                    }
                                    $aCiphers += [PSCustomObject]@{
                                        Protocol = $sProto
                                        Name     = [string]$hElems['name']
                                        Strength = $null
                                        Quality  = [string]$hElems['strength']
                                        KexInfo  = [string]$hElems['kex_info']
                                    }
                                }
                            }
                        }
                        foreach ($oEl in @($oScript.elem)) {
                            if ($oEl.key -eq 'least strength') { $sLeastStrength = [string]$oEl.'#text' }
                        }
                    }
                    'ssl-cert' {
                        $hElems = @{}
                        foreach ($oEl in @($oScript.elem)) {
                            if ($null -ne $oEl.key -and $oEl.key -ne '') {
                                $hElems[[string]$oEl.key] = [string]$oEl.'#text'
                            }
                        }
                        foreach ($oTable in @($oScript.table)) {
                            if (-not $oTable.key) { continue }
                            $hSub = @{}
                            foreach ($oEl in @($oTable.elem)) {
                                if ($null -ne $oEl.key -and $oEl.key -ne '') {
                                    $hSub[[string]$oEl.key] = [string]$oEl.'#text'
                                }
                            }
                            $hElems[[string]$oTable.key] = $hSub
                        }
                        $oSubject = $hElems['subject']
                        $oIssuer  = $hElems['issuer']
                        $oValidity = $hElems['validity']
                        $oPubkey   = $hElems['pubkey']
                        $oCert = [PSCustomObject]@{
                            Subject  = if ($oSubject -is [hashtable]) { ($oSubject.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ' } else { [string]$hElems['commonName'] }
                            Issuer   = if ($oIssuer  -is [hashtable]) { ($oIssuer.GetEnumerator()  | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ' } else { $null }
                            NotAfter = if ($oValidity -is [hashtable]) { [string]$oValidity['notAfter'] } else { [string]$hElems['validity'] }
                            KeyAlgo  = if ($oPubkey   -is [hashtable]) { [string]$oPubkey['type'] }     else { [string]$hElems['pubkey'] }
                            KeyBits  = if ($oPubkey   -is [hashtable] -and $oPubkey['bits']) { [int]$oPubkey['bits'] } else { $null }
                        }
                    }
                }
            }

            New-NmapResult -ResHost $sUserName -ResPort $Port -Raw $sXml `
                -LeastStrength $sLeastStrength -Protocols $hProtocols `
                -CipherSuites $aCiphers -Cert $oCert
        }

        # Emit an explicit miss for inputs that didn't surface in the
        # XML at all (so the caller's input/output count matches).
        foreach ($sH in $ComputerName) {
            if (-not $hHostsSeen.ContainsKey($sH.ToLower())) {
                New-NmapResult -ResHost $sH -ResPort $Port -Err "host not present in nmap output" -Raw $sXml
            }
        }
    }
}
