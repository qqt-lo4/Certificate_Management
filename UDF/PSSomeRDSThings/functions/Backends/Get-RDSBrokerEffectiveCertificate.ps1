function Get-RDSBrokerEffectiveCertificate {
    <#
    .SYNOPSIS
    Reads the certificate actually used by the RD Gateway and RD Web Access services of a server.

    .DESCRIPTION
    Get-RemoteDesktopCertificate returns what the deployment (RDMS) records. This function checks
    what the services hosted on the target server really use, with local commands only (no second
    hop):
      - RDGateway   : Win32_TSGatewayServerSettings.CertHash (only when the TSGateway service exists)
      - RDWebAccess : https bindings of 'Default Web Site' (WebAdministration), or the 0.0.0.0:443
                      binding from "netsh http show sslcert" as a fallback (only when W3SVC exists).
                      "MIXED(...)" when the bindings use different certificates.

    A role whose service is not on this server (or cannot be read) is absent from the result.

    Internal backend: used by Set-RDSBrokerCertificate to verify a deployment.

    .PARAMETER Session
    A PSSession opened to the server (standard endpoint).

    .OUTPUTS
    [hashtable] Role -> thumbprint (upper case).

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-10-25 - Loïc Ade
            - Initial release
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )
    $hResult = Invoke-Command -Session $Session -ScriptBlock {
        $h = @{}
        if (Get-Service -Name TSGateway -ErrorAction SilentlyContinue) {
            try {
                $oGW = Get-CimInstance -Namespace 'root\cimv2\TerminalServices' -ClassName 'Win32_TSGatewayServerSettings' -ErrorAction Stop |
                    Select-Object -First 1
                if ($oGW -and $oGW.CertHash) {
                    $h.RDGateway = (($oGW.CertHash | ForEach-Object { ([byte]$_).ToString('X2') }) -join '')
                }
            } catch { }
        }
        if (Get-Service -Name W3SVC -ErrorAction SilentlyContinue) {
            # IIS view first (covers IP and SNI bindings of the RD Web site), netsh as a fallback
            try {
                Import-Module WebAdministration -ErrorAction Stop
                $aHashes = @(Get-WebBinding -Name 'Default Web Site' -Protocol https -ErrorAction Stop |
                    Where-Object { $_.certificateHash } | ForEach-Object { ([string]$_.certificateHash).ToUpper() })
                # Bindings on different certificates: report "MIXED(...)", which never matches a
                # thumbprint, so the caller sees a mismatch
                $aUnique = @($aHashes | Sort-Object -Unique)
                if ($aUnique.Count -eq 1) { $h.RDWebAccess = $aUnique[0] }
                elseif ($aUnique.Count -gt 1) { $h.RDWebAccess = "MIXED(" + ($aUnique -join ",") + ")" }
            } catch { }
            if (-not $h.RDWebAccess) {
                $aOut = & netsh.exe http show sslcert ipport=0.0.0.0:443 2>$null
                # Locale-independent: take the first 40-hex-digit value of the output
                $oMatch = $aOut | Select-String -Pattern '\b[0-9a-fA-F]{40}\b' | Select-Object -First 1
                if ($oMatch) { $h.RDWebAccess = $oMatch.Matches[0].Value.ToUpper() }
            }
        }
        return $h
    }
    if ($hResult -is [hashtable]) { return $hResult }
    # Deserialized hashtable safety net
    $hCopy = @{}
    if ($hResult) { foreach ($k in $hResult.Keys) { $hCopy[$k] = $hResult[$k] } }
    return $hCopy
}
