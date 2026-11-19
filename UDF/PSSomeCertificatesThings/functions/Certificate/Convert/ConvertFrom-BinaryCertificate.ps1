function ConvertFrom-BinaryCertificate {
    <#
    .SYNOPSIS
        Decodes DER-encoded certificate bytes into certificate metadata.

    .PARAMETER Bytes
        DER-encoded X.509 certificate bytes.

    .PARAMETER Source
        Optional source label attached to the returned metadata.

    .OUTPUTS
        PSCustomObject with the certificate metadata and original DER bytes.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [byte[]]$Bytes,
        [string]$Source = ''
    )

    $oCert = $null
    $oPublicKey = $null
    try {
        $oCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$Bytes)
        $iKeySize = $null
        try {
            $oPublicKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($oCert)
            if ($oPublicKey) { $iKeySize = $oPublicKey.KeySize }
        } catch {}
        if (-not $oPublicKey) {
            try {
                $oPublicKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($oCert)
                if ($oPublicKey) { $iKeySize = $oPublicKey.KeySize }
            } catch {}
        }
        [PSCustomObject][ordered]@{
            source = $Source
            subject = $oCert.Subject
            issuer = $oCert.Issuer
            notBefore = $oCert.NotBefore
            notAfter = $oCert.NotAfter
            serialNumber = $oCert.SerialNumber
            thumbprint = $oCert.Thumbprint
            signatureAlgorithm = $oCert.SignatureAlgorithm.FriendlyName
            keySize = $iKeySize
            version = $oCert.Version
            hasPrivateKey = $oCert.HasPrivateKey
            rawData = [byte[]]$oCert.RawData
        }
    } catch {
        Write-Verbose "Failed to decode certificate from $Source : $_"
        return $null
    } finally {
        if ($oPublicKey -and $oPublicKey -is [System.IDisposable]) { $oPublicKey.Dispose() }
        if ($oCert) { $oCert.Dispose() }
    }
}
