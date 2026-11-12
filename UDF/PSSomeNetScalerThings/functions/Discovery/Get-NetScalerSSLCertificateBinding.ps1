function Get-NetScalerSSLCertificateBinding {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [object]$Session,
        [Parameter(Mandatory)]
        [string]$VirtualServer
    )

    $oResponse = Invoke-NetScalerNitroApi -Session $Session -Resource 'sslvserver_sslcertkey_binding' -Identifier $VirtualServer
    return @($oResponse.sslvserver_sslcertkey_binding)
}