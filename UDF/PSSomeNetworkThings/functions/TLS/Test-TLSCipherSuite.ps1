function Test-TLSCipherSuite {
    <#
    .SYNOPSIS
        Tests the TLS configuration (protocols, cipher suites,
        certificate, known vulnerabilities) of a remote host via a
        pluggable scanning source.

    .DESCRIPTION
        Dispatcher that delegates the actual scan to one of the
        registered Test-TLSCipherSuite_<Source> helpers. Adding a new
        source (testssl.sh, Mozilla Observatory, pure-PowerShell
        SslStream probe, ...) is a one-file drop next to this script
        plus a new entry in the -Source ValidateSet.

        Sources currently shipped:
          - Nmap     : local nmap binary running
            "--script ssl-enum-ciphers". Best for internal targets
            (no proxy interference, fast, free).
          - SSLLabs  : Qualys SSL Labs public API. Best for external
            targets where you want a vantage point from the public
            Internet (matches what end users outside the corp
            network experience).

        Every source returns the same PSCustomObject shape so the
        downstream consumer (Export-TLSAudit report) does not have
        to special-case per provider.

    .PARAMETER ComputerName
        Target hostname or IP. FQDN preferred (SSLLabs requires it).

    .PARAMETER Port
        TCP port to probe. Default 443.

    .PARAMETER Source
        Which scanning backend to use. Valid values:
            Nmap     - local nmap with ssl-enum-ciphers script
            SSLLabs  - Qualys SSL Labs public API

    .OUTPUTS
        [PSCustomObject] with at least the following fields:
            Host             : input hostname
            Port             : input port
            Source           : which scanner ran the test
            ScanDate         : timestamp of the result
            Grade            : overall grade if the source computes one,
                               $null otherwise (Nmap returns LeastStrength
                               instead)
            LeastStrength    : weakest cipher strength letter, when the
                               source surfaces it
            Protocols        : hashtable { "TLSv1.0" = $bool; ... }
            CipherSuites     : array of @{ Protocol; Name; Strength; Quality; KexInfo }
            Certificate      : @{ Subject; Issuer; NotAfter; KeyAlgo; KeyBits }
            Vulnerabilities  : hashtable { Heartbleed = $bool; POODLE = ... },
                               $null when the source doesn't check
            ScanError        : $null on success, error string when the scan failed
            RawResponse      : passthrough of the source's raw output for debug

    .EXAMPLE
        Test-TLSCipherSuite -ComputerName frpscm01.example.com -Source Nmap

    .EXAMPLE
        Test-TLSCipherSuite -ComputerName pam.example.com -Source SSLLabs

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-06-15, Loic Ade) - Initial version. Dispatcher
                             + Nmap + SSL Labs sources.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [int]$Port = 443,

        [Parameter(Mandatory)]
        [ValidateSet('Nmap','SSLLabs')]
        [string]$Source,

        # SSLLabs-specific options. Silently ignored on other sources.
        # Exposed on the dispatcher so the caller has autocomplete +
        # short syntax (-UseCache) without juggling a backend args
        # hashtable.
        [switch]$UseCache,

        [int]$PollIntervalSeconds = 10,

        [int]$MaxPollMinutes = 5
    )
    Process {
        $sFn = "Test-TLSCipherSuite_$Source"
        if (-not (Get-Command $sFn -ErrorAction SilentlyContinue)) {
            throw "Test-TLSCipherSuite : backend '$sFn' not found - is the matching helper loaded?"
        }

        # Backend-specific params: only forward what the chosen
        # backend declares. Each new -Source extension adds its
        # block here.
        $hExtra = @{}
        switch ($Source) {
            'SSLLabs' {
                if ($UseCache.IsPresent) { $hExtra['UseCache'] = $true }
                if ($PSBoundParameters.ContainsKey('PollIntervalSeconds')) { $hExtra['PollIntervalSeconds'] = $PollIntervalSeconds }
                if ($PSBoundParameters.ContainsKey('MaxPollMinutes'))      { $hExtra['MaxPollMinutes']      = $MaxPollMinutes }
            }
        }

        & $sFn -ComputerName $ComputerName -Port $Port @hExtra
    }
}
