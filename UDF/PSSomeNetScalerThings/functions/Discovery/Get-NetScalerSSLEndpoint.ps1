function Get-NetScalerSSLEndpoint {
    <#
    .SYNOPSIS
        Discovers candidate HTTPS/TLS endpoints and SNI names configured on a NetScaler ADC.
    .PARAMETER Session
        Authenticated session returned by Connect-NetScalerNitroSession.
    .OUTPUTS
        Objects with VirtualServer, VirtualServerType, VIP, Port, HostName,
        ServiceType, State, CertificateKey, and DiscoverySource properties.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [object]$Session
    )

    $aEndpoints = @()
    foreach ($oVServer in Get-NetScalerSSLVirtualServer -Session $Session) {
        $hHostNames = @{}
        try {
            foreach ($oBinding in Get-NetScalerSSLCertificateBinding -Session $Session -VirtualServer $oVServer.Name) {
                $sSniName = ([string]$oBinding.servername).Trim().TrimEnd('.')
                if ($sSniName -and $sSniName -notmatch '\*') {
                    $hHostNames[$sSniName.ToLowerInvariant()] = [PSCustomObject]@{
                        HostName = $sSniName
                        CertificateKey = $oBinding.certkeyname
                        DiscoverySource = 'SNI certificate binding'
                    }
                }
            }
        } catch {
            Write-Warning "Could not read SSL certificate bindings for '$($oVServer.Name)': $_"
        }

        if ($oVServer.Type -eq 'csvserver') {
            foreach ($oHost in Get-NetScalerContentSwitchHostname -Session $Session -VirtualServer $oVServer.Name) {
                if (-not $hHostNames.ContainsKey($oHost.HostName.ToLowerInvariant())) {
                    $hHostNames[$oHost.HostName.ToLowerInvariant()] = $oHost
                }
            }
        }

        if ($hHostNames.Count -eq 0) {
            $sFallbackHost = if ($oVServer.Name -match '^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$') {
                $oVServer.Name
            } else {
                $oVServer.VIP
            }
            if (-not $sFallbackHost) { continue }
            $hHostNames[$sFallbackHost.ToLowerInvariant()] = [PSCustomObject]@{
                HostName = $sFallbackHost
                CertificateKey = $null
                DiscoverySource = if ($sFallbackHost -eq $oVServer.VIP) { 'vServer VIP (default certificate)' } else { 'vServer name' }
            }
        }

        foreach ($oHost in $hHostNames.Values) {
            $aEndpoints += [PSCustomObject]@{
                VirtualServer = $oVServer.Name
                VirtualServerType = $oVServer.Type
                VIP = $oVServer.VIP
                Port = $oVServer.Port
                ServiceType = $oVServer.ServiceType
                State = $oVServer.State
                HostName = $oHost.HostName
                CertificateKey = $oHost.CertificateKey
                DiscoverySource = $oHost.DiscoverySource
            }
        }
    }

    return @($aEndpoints | Sort-Object VirtualServer, HostName, Port -Unique)
}