function Get-CertificateFromRDP {
    <#
    .SYNOPSIS
        Retrieves the certificate presented by an RDP listener.

    .DESCRIPTION
        Negotiates RDP TLS or CredSSP, then reads the server certificate during
        the TLS handshake. No RDP login or credentials are sent. The certificate
        is returned without validating its trust chain, for inspection purposes.

    .PARAMETER ComputerName
        DNS name or IP address of the RDP server.

    .PARAMETER Port
        RDP TCP port. Default: 3389.

    .PARAMETER TimeoutSeconds
        Timeout for each network operation. Default: 10 seconds.
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [ValidateRange(1, 65535)]
        [int]$Port = 3389,

        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 10
    )

    $sHostName = $ComputerName.Trim('[', ']')
    $iTimeoutMs = $TimeoutSeconds * 1000
    $oTcpClient = New-Object System.Net.Sockets.TcpClient
    try {
        $oConnect = $oTcpClient.BeginConnect($sHostName, $Port, $null, $null)
        if (-not $oConnect.AsyncWaitHandle.WaitOne($iTimeoutMs)) {
            throw "Cannot connect to $sHostName on TCP port $Port (timeout)."
        }
        $oTcpClient.EndConnect($oConnect)
        $oTcpClient.ReceiveTimeout = $iTimeoutMs
        $oTcpClient.SendTimeout = $iTimeoutMs
        $oStream = $oTcpClient.GetStream()

        $aRequest = [byte[]]@(0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00)
        $oStream.Write($aRequest, 0, $aRequest.Length)

        $aHeader = New-Object byte[] 4
        $iRead = 0
        while ($iRead -lt $aHeader.Length) {
            $iCount = $oStream.Read($aHeader, $iRead, $aHeader.Length - $iRead)
            if ($iCount -le 0) { throw 'RDP server closed the connection during negotiation.' }
            $iRead += $iCount
        }
        $iLength = ([int]$aHeader[2] -shl 8) -bor [int]$aHeader[3]
        if ($aHeader[0] -ne 3 -or $aHeader[1] -ne 0 -or $iLength -lt 11) {
            throw 'Invalid RDP TPKT negotiation response.'
        }

        $aResponse = New-Object byte[] ($iLength - 4)
        $iRead = 0
        while ($iRead -lt $aResponse.Length) {
            $iCount = $oStream.Read($aResponse, $iRead, $aResponse.Length - $iRead)
            if ($iCount -le 0) { throw 'RDP server closed the connection during negotiation.' }
            $iRead += $iCount
        }
        if ($aResponse[1] -ne 0xd0 -or ([int]$aResponse[0] + 1) -ne $aResponse.Length) {
            throw 'Invalid RDP X.224 connection confirmation.'
        }
        if ($aResponse.Length -eq 7) { throw 'The RDP server selected standard RDP security; no TLS certificate was presented.' }
        if ($aResponse.Length -ne 15 -or $aResponse[9] -ne 8 -or $aResponse[10] -ne 0) {
            throw 'Invalid RDP security negotiation response.'
        }
        $iSelectedProtocol = [BitConverter]::ToUInt32($aResponse, 11)
        if ($aResponse[7] -eq 3) { throw "RDP security negotiation failed (code $iSelectedProtocol)." }
        if ($aResponse[7] -ne 2 -or $iSelectedProtocol -notin @(1, 2, 8)) {
            throw "RDP server selected unsupported security protocol $iSelectedProtocol."
        }

        $oCallback = [System.Net.Security.RemoteCertificateValidationCallback]{ $true }
        $oSslStream = New-Object System.Net.Security.SslStream($oStream, $false, $oCallback)
        try {
            $oSslStream.AuthenticateAsClient($sHostName)
            if (-not $oSslStream.RemoteCertificate) { throw 'RDP server did not present a TLS certificate.' }
            return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $oSslStream.RemoteCertificate.GetRawCertData())
        }
        finally {
            $oSslStream.Dispose()
        }
    }
    finally {
        $oTcpClient.Close()
    }
}