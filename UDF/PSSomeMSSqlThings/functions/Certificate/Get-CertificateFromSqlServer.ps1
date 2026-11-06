function Get-CertificateFromSqlServer {
    <#
    .SYNOPSIS
        Retrieves the X.509 certificate presented by a SQL Server instance

    .DESCRIPTION
        Connects to a SQL Server instance and performs the TLS handshake the way a client does,
        then returns the server certificate as a System.Security.Cryptography.X509Certificates.X509Certificate2.
        No login is sent and no credential is needed.

        SQL Server does not speak TLS directly: the TLS handshake is carried inside TDS PRELOGIN
        packets, after a PRELOGIN exchange where client and server agree on encryption. This
        function implements that exchange. When it fails, a direct TLS connection is tried, for
        SQL Server 2022 instances in strict encryption mode (TDS 8.0).

        The port is resolved as follows: the Port parameter when given; otherwise the SQL Server
        Browser service (UDP 1434) for a named instance; otherwise 1433.

        The certificate trust chain is not validated (any certificate is accepted) because the goal
        is to inspect the certificate, not to establish a secure session. When no certificate is
        configured, SQL Server presents a self-generated one ("SSL_Self_Signed_Fallback").

    .PARAMETER ComputerName
        Name or IP address of the SQL Server.

    .PARAMETER InstanceName
        Name of the instance. Empty or MSSQLSERVER designates the default instance.

    .PARAMETER Port
        TCP port of the instance. When given, the SQL Server Browser is not queried.

    .PARAMETER TimeoutSeconds
        Timeout of each network operation. Default: 10.

    .PARAMETER TdsOnly
        Do not try a direct TLS connection when the TDS exchange fails. Useful to tell a SQL Server
        from another TLS service on the same port (any TLS server answers a direct TLS connection).

    .OUTPUTS
        [System.Security.Cryptography.X509Certificates.X509Certificate2]. The server certificate.

    .EXAMPLE
        Get-CertificateFromSqlServer -ComputerName "sql01.contoso.com"

    .EXAMPLE
        Get-CertificateFromSqlServer -ComputerName "sql01" -InstanceName "SCCM"

    .EXAMPLE
        (Get-CertificateFromSqlServer "sql01" -Port 14330).NotAfter

    .NOTES
        Author  : Loïc Ade
        Version : 1.1.0

        CHANGELOG:

        Version 1.1.0 - 2026-11-06 - Loïc Ade
            - New TdsOnly switch: no direct TLS fallback
            - Moved from PSSomeCertificatesThings to PSSomeMSSqlThings

        Version 1.0.0 - 2026-11-06 - Loïc Ade
            - Initial release
            - TLS handshake inside TDS PRELOGIN packets, direct TLS fallback (TDS 8.0 strict)
            - Named instance port resolved with the SQL Server Browser
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$ComputerName,
        [string]$InstanceName,
        [ValidateRange(1, 65535)]
        [int]$Port,
        [ValidateRange(1, 300)]
        [int]$TimeoutSeconds = 10,
        [switch]$TdsOnly
    )
    Begin {
        # Stream that carries the TLS handshake inside TDS PRELOGIN packets (type 0x12)
        if (-not ("PSSomeMSSqlThings.TdsPreloginStream" -as [type])) {
            Add-Type -TypeDefinition @"
using System;
using System.IO;

namespace PSSomeMSSqlThings {
    public class TdsPreloginStream : Stream {
        private readonly Stream _inner;
        private byte[] _buffer = new byte[0];
        private int _offset = 0;
        private byte _packetId = 1;

        public TdsPreloginStream(Stream inner) { _inner = inner; }

        private static void ReadExact(Stream stream, byte[] buffer, int offset, int count) {
            while (count > 0) {
                int read = stream.Read(buffer, offset, count);
                if (read <= 0) { throw new EndOfStreamException("The server closed the connection"); }
                offset += read;
                count -= read;
            }
        }

        // Reads one TDS packet and returns its payload
        public static byte[] ReadPacket(Stream stream, out byte type) {
            byte[] header = new byte[8];
            ReadExact(stream, header, 0, 8);
            type = header[0];
            int length = (header[2] << 8) | header[3];
            if (length < 8) { throw new InvalidDataException("Invalid TDS packet length: " + length); }
            byte[] payload = new byte[length - 8];
            ReadExact(stream, payload, 0, payload.Length);
            return payload;
        }

        // Writes one TDS packet (end of message) holding the given payload
        public static void WritePacket(Stream stream, byte type, byte[] data, int offset, int count, byte packetId) {
            byte[] packet = new byte[count + 8];
            packet[0] = type;
            packet[1] = 0x01;
            packet[2] = (byte)((count + 8) >> 8);
            packet[3] = (byte)((count + 8) & 0xFF);
            packet[6] = packetId;
            Buffer.BlockCopy(data, offset, packet, 8, count);
            stream.Write(packet, 0, packet.Length);
            stream.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count) {
            while (_offset >= _buffer.Length) {
                byte type;
                _buffer = ReadPacket(_inner, out type);
                _offset = 0;
            }
            int n = Math.Min(count, _buffer.Length - _offset);
            Buffer.BlockCopy(_buffer, _offset, buffer, offset, n);
            _offset += n;
            return n;
        }

        public override void Write(byte[] buffer, int offset, int count) {
            const int maxPayload = 4096 - 8;
            while (count > 0) {
                int n = Math.Min(count, maxPayload);
                WritePacket(_inner, 0x12, buffer, offset, n, _packetId++);
                offset += n;
                count -= n;
            }
        }

        public override bool CanRead { get { return true; } }
        public override bool CanWrite { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
        public override void Flush() { _inner.Flush(); }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
    }
}
"@
        }

        function Resolve-SqlInstancePort {
            # Asks the SQL Server Browser (UDP 1434) for the TCP port of a named instance
            Param([string]$ComputerName, [string]$InstanceName, [int]$TimeoutMs)
            $oUdp = New-Object System.Net.Sockets.UdpClient
            try {
                $oUdp.Client.ReceiveTimeout = $TimeoutMs
                $oUdp.Connect($ComputerName, 1434)
                # CLNT_UCAST_INST: 0x04 followed by the instance name
                $aRequest = [byte[]](@(0x04) + [System.Text.Encoding]::ASCII.GetBytes($InstanceName))
                $oUdp.Send($aRequest, $aRequest.Length) | Out-Null
                $oRemote = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
                $aResponse = try {
                    $oUdp.Receive([ref]$oRemote)
                } catch {
                    # The Browser does not answer for an unknown instance either
                    throw "No answer from the SQL Server Browser of $ComputerName for instance $InstanceName (unknown instance, service stopped or UDP 1434 blocked): give the port of the instance instead"
                }
                # SVR_RESP: 0x05, 2 bytes length, then "ServerName;X;InstanceName;Y;...;tcp;<port>;..."
                $sResponse = [System.Text.Encoding]::ASCII.GetString($aResponse, 3, $aResponse.Length - 3)
                if ($sResponse -match "(?i)(?:^|;)tcp;([0-9]+)") {
                    return [int]$Matches[1]
                }
                throw "Instance $InstanceName on $ComputerName does not listen on TCP (SQL Server Browser answer: $sResponse)"
            } finally {
                $oUdp.Close()
            }
        }

        function Connect-SqlTcp {
            Param([string]$ComputerName, [int]$Port, [int]$TimeoutMs)
            $oTcp = New-Object System.Net.Sockets.TcpClient
            $oAsync = $oTcp.BeginConnect($ComputerName, $Port, $null, $null)
            if (-not $oAsync.AsyncWaitHandle.WaitOne($TimeoutMs)) {
                $oTcp.Close()
                throw "Cannot connect to $ComputerName on TCP port $Port (timeout)"
            }
            try {
                $oTcp.EndConnect($oAsync)
            } catch {
                $oTcp.Close()
                $oInner = $_.Exception
                while ($oInner.InnerException) { $oInner = $oInner.InnerException }
                throw "Cannot connect to $ComputerName on TCP port ${Port}: $($oInner.Message)"
            }
            $oTcp.ReceiveTimeout = $TimeoutMs
            $oTcp.SendTimeout = $TimeoutMs
            return $oTcp
        }

        function Invoke-TlsHandshake {
            # Runs the TLS handshake over $Stream and returns the server certificate
            Param([System.IO.Stream]$Stream, [string]$TargetHost)
            $oCallback = [System.Net.Security.RemoteCertificateValidationCallback]{ $true }
            $oSsl = New-Object System.Net.Security.SslStream($Stream, $true, $oCallback)
            try {
                try {
                    # None = protocols chosen by the operating system (.NET Framework 4.7+ / .NET Core)
                    $oSsl.AuthenticateAsClient($TargetHost, $null, [System.Security.Authentication.SslProtocols]::None, $false)
                } catch [System.ArgumentException] {
                    $eProtocols = [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls11 -bor [System.Security.Authentication.SslProtocols]::Tls
                    $oSsl.AuthenticateAsClient($TargetHost, $null, $eProtocols, $false)
                }
                if (-not $oSsl.RemoteCertificate) {
                    throw "The server did not present a certificate"
                }
                return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 (, $oSsl.RemoteCertificate.GetRawCertData())
            } finally {
                $oSsl.Dispose()
            }
        }
    }
    Process {
        $iTimeoutMs = $TimeoutSeconds * 1000
        $iPort = if ($Port) {
            $Port
        } elseif ($InstanceName -and ($InstanceName -ne "MSSQLSERVER")) {
            Resolve-SqlInstancePort -ComputerName $ComputerName -InstanceName $InstanceName -TimeoutMs $iTimeoutMs
        } else {
            1433
        }
        Write-Verbose "Connecting to $ComputerName on TCP port $iPort"

        # 1. TDS: PRELOGIN exchange, then the TLS handshake inside PRELOGIN packets
        $oTdsError = $null
        $oTcp = Connect-SqlTcp -ComputerName $ComputerName -Port $iPort -TimeoutMs $iTimeoutMs
        try {
            $oNet = $oTcp.GetStream()
            # PRELOGIN options: VERSION (offset 11, 6 bytes), ENCRYPTION (offset 17, 1 byte), terminator,
            # then the data: client version 0.0.0.0, ENCRYPT_ON
            $aPrelogin = [byte[]](0x00, 0x00, 0x0B, 0x00, 0x06,
                                  0x01, 0x00, 0x11, 0x00, 0x01,
                                  0xFF,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                  0x01)
            [PSSomeMSSqlThings.TdsPreloginStream]::WritePacket($oNet, 0x12, $aPrelogin, 0, $aPrelogin.Length, 1)
            $bType = [byte]0
            $aResponse = [PSSomeMSSqlThings.TdsPreloginStream]::ReadPacket($oNet, [ref]$bType)

            # ENCRYPTION option of the answer: 0 OFF (login only), 1 ON, 2 NOT_SUP, 3 REQ
            $iEncryption = -1
            $i = 0
            while (($i + 4) -lt $aResponse.Length -and $aResponse[$i] -ne 0xFF) {
                $iOffset = ($aResponse[$i + 1] -shl 8) -bor $aResponse[$i + 2]
                if (($aResponse[$i] -eq 0x01) -and ($iOffset -lt $aResponse.Length)) {
                    $iEncryption = $aResponse[$iOffset]
                }
                $i += 5
            }
            Write-Verbose "PRELOGIN answer: encryption = $iEncryption"
            if ($iEncryption -eq 2) {
                throw "SQL Server on $ComputerName (port $iPort) does not support encryption: it has no certificate"
            }
            if ($iEncryption -lt 0) {
                throw "Unexpected PRELOGIN answer from $ComputerName (port $iPort)"
            }
            $oTds = New-Object PSSomeMSSqlThings.TdsPreloginStream($oNet)
            return Invoke-TlsHandshake -Stream $oTds -TargetHost $ComputerName
        } catch {
            $oTdsError = $_
            Write-Verbose "TDS PRELOGIN failed: $_"
        } finally {
            $oTcp.Close()
        }

        # 2. Direct TLS: SQL Server 2022 in strict encryption mode (TDS 8.0)
        if ($TdsOnly -or ($oTdsError.Exception.Message -like "*does not support encryption*")) { throw $oTdsError }
        $oTcp = Connect-SqlTcp -ComputerName $ComputerName -Port $iPort -TimeoutMs $iTimeoutMs
        try {
            return Invoke-TlsHandshake -Stream $oTcp.GetStream() -TargetHost $ComputerName
        } catch {
            throw "Cannot read the certificate of SQL Server on $ComputerName (port $iPort): $($oTdsError.Exception.Message)"
        } finally {
            $oTcp.Close()
        }
    }
}
