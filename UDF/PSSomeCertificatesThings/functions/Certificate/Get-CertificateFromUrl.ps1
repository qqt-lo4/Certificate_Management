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

    .PARAMETER TimeoutSeconds
        Timeout of the connection and of each read / write during the TLS handshake. Default: 10.
        Without it a server that does not speak TLS and does not close the connection (e.g. a
        SQL Server port) blocks the call.

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
        Version : 1.1.0

        CHANGELOG:

        Version 1.1.0 - 2026-11-06 - Loïc Ade
            - New TimeoutSeconds parameter (default 10) for the connection and the handshake: the
              call could wait indefinitely on a server that neither answers nor closes

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
        [string]$Url,
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 10
    )
    $uri = [Uri]$Url
    $iTimeoutMs = $TimeoutSeconds * 1000
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    try {
        $oAsync = $tcpClient.BeginConnect($uri.Host, $uri.Port, $null, $null)
        if (-not $oAsync.AsyncWaitHandle.WaitOne($iTimeoutMs)) {
            throw "Cannot connect to $($uri.Host) on port $($uri.Port) (timeout)"
        }
        try {
            $tcpClient.EndConnect($oAsync)
        } catch {
            $oInner = $_.Exception
            while ($oInner.InnerException) { $oInner = $oInner.InnerException }
            throw "Cannot connect to $($uri.Host) on port $($uri.Port): $($oInner.Message)"
        }
        # Read / write timeouts also bound the TLS handshake
        $tcpClient.ReceiveTimeout = $iTimeoutMs
        $tcpClient.SendTimeout = $iTimeoutMs
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
