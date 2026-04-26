function Get-CertificateFromUrl {
    <#
    .SYNOPSIS
        Retrieves the X.509 certificate presented by an HTTPS endpoint

    .DESCRIPTION
        Opens a TCP+TLS connection to the given HTTPS URL, performs the TLS handshake
        and returns the remote server certificate as a System.Security.Cryptography.X509Certificates.X509Certificate2.
        The certificate trust chain is not validated (any certificate is accepted) because the goal is
        to inspect / import the certificate, not to establish a secure session.

    .PARAMETER Url
        The HTTPS URL of the endpoint to query. The port is taken from the URL
        (defaults to 443 when omitted).

    .OUTPUTS
        [System.Security.Cryptography.X509Certificates.X509Certificate2]. The remote server certificate.

    .EXAMPLE
        Get-CertificateFromUrl -Url "https://example.com"

    .EXAMPLE
        $cert = Get-CertificateFromUrl -Url "https://server.local:8443"
        $cert.Subject
        $cert.NotAfter

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-04-22 - Loïc Ade
            - Initial release
            - Fetches remote server certificate via TCP + SslStream handshake
            - Server certificate validation disabled (inspection use case)
            - Port defaults to 443 when omitted from the URL
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [ValidatePattern('^https://')]
        [string]$Url
    )
    $uri = [Uri]$Url
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    try {
        $tcpClient.Connect($uri.Host, $uri.Port)
        $callback = [System.Net.Security.RemoteCertificateValidationCallback]{ $true }
        $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, $callback)
        try {
            $sslStream.AuthenticateAsClient($uri.Host)
            $oRaw = $sslStream.RemoteCertificate
            if (-not $oRaw) {
                throw "Remote endpoint did not present a certificate"
            }
            return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $oRaw.GetRawCertData())
        } finally {
            $sslStream.Dispose()
        }
    } finally {
        $tcpClient.Close()
    }
}
