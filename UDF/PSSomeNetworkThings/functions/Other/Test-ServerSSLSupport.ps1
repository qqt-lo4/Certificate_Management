function Test-ServerSSLSupport {
    <#
    .SYNOPSIS
        Tests SSL/TLS protocol support on a server

    .DESCRIPTION
        Connects to a server and tests which SSL/TLS protocols are supported
        (SSLv2, SSLv3, TLS 1.0, 1.1, 1.2, 1.3). Returns the supported protocols
        along with key exchange and hash algorithm information.

    .PARAMETER HostName
        The server hostname or IP address to test.

    .PARAMETER Port
        The port to connect to (default: 443).

    .OUTPUTS
        [PSObject]. Object with Host, Port, KeyExchange, HashAlgorithm, and boolean properties for each protocol.

    .EXAMPLE
        Test-ServerSSLSupport -HostName "example.com"

    .EXAMPLE
        "server1", "server2" | Test-ServerSSLSupport -Port 8443

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$HostName,
        [UInt16]$Port = 443
    )
    begin {
        function Test-ServerSSLSupport_OneProtocol {
            Param(
                [Parameter(Mandatory)]
                [string]$Name,
                [Parameter(Mandatory)]
                [string]$DisplayName,
                [Parameter(Mandatory)]
                [ref]$HashtableResult
            )
            $TcpClient = New-Object Net.Sockets.TcpClient
            $TcpClient.Connect($HashtableResult.Value.Host, $HashtableResult.Value.Port)
            $SslStream = New-Object Net.Security.SslStream $TcpClient.GetStream(),
                $true,
                ([System.Net.Security.RemoteCertificateValidationCallback]{ $true })
            $SslStream.ReadTimeout = 15000
            $SslStream.WriteTimeout = 15000
            try {
                $SslStream.AuthenticateAsClient($HashtableResult.Value.Host,$null,$Name,$false)
                $HashtableResult.Value.KeyExhange = $SslStream.KeyExchangeAlgorithm
                $HashtableResult.Value.HashAlgorithm = $SslStream.HashAlgorithm
                $status = $true
            } catch {
                $status = $false
            }
            $HashtableResult.Value.Add($DisplayName, $status)
            # dispose objects to prevent memory leaks
            $TcpClient.Dispose()
            $SslStream.Dispose()
        }   
    }
    process {
        $RetValue = [ordered]@{
            Host = $HostName
            Port = $Port
            KeyExhange = $null
            HashAlgorithm = $null
        }
        Test-ServerSSLSupport_OneProtocol -Name "ssl2" -DisplayName "SSLv2" -HashtableResult ([ref]$RetValue)
        Test-ServerSSLSupport_OneProtocol -Name "ssl3" -DisplayName "SSLv3" -HashtableResult ([ref]$RetValue)
        Test-ServerSSLSupport_OneProtocol -Name "tls" -DisplayName "TLSv1_0" -HashtableResult ([ref]$RetValue)
        Test-ServerSSLSupport_OneProtocol -Name "tls11" -DisplayName "TLSv1_1" -HashtableResult ([ref]$RetValue)
        Test-ServerSSLSupport_OneProtocol -Name "tls12" -DisplayName "TLSv1_2" -HashtableResult ([ref]$RetValue)
        Test-ServerSSLSupport_OneProtocol -Name "tls13" -DisplayName "TLSv1_3" -HashtableResult ([ref]$RetValue)
        return New-Object psobject -Property $RetValue
    }
}