function Get-IssuerCertificate {
    <#
    .SYNOPSIS
        Retrieves the issuer certificate from a certificate chain

    .DESCRIPTION
        Gets the issuer certificate for a given X509Certificate2 object by building
        the certificate chain. Returns the certificate itself if it's self-signed.
        Revocation checking is disabled for chain building.

    .PARAMETER Cert
        The X509Certificate2 object to find the issuer for.

    .OUTPUTS
        [System.Security.Cryptography.X509Certificates.X509Certificate2]. The issuer certificate or the certificate itself if self-signed.

    .EXAMPLE
        $cert = Get-Item Cert:\LocalMachine\My\THUMBPRINT
        $issuer = Get-IssuerCertificate -Cert $cert

    .EXAMPLE
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("C:\Certs\cert.cer")
        $issuer = Get-IssuerCertificate -Cert $cert

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )
    if ($Cert.Subject -eq $Cert.Issuer) { 
        return $Cert 
    }
    [System.Security.Cryptography.X509Certificates.X509Chain]$chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck;
    $chain.Build($Cert) | Out-Null
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$issuer = $null
    if ($chain.ChainElements.Count -gt 1) {
        $issuer = $chain.ChainElements[1].Certificate;
    }
    return $issuer
}