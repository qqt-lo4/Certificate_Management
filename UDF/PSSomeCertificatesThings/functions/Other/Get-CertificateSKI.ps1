function Get-CertificateSKI {
    <#
    .SYNOPSIS
        Returns the SubjectKeyIdentifier of an X.509 certificate as an uppercase hex string

    .DESCRIPTION
        Reads the SubjectKeyIdentifier extension (OID 2.5.29.14) from the certificate and
        returns its key identifier bytes as an uppercase hex string. When .NET exposes the
        extension as the strongly typed X509SubjectKeyIdentifierExtension the SubjectKeyIdentifier
        property is used directly; otherwise the extension's RawData is parsed as an OCTET STRING.

    .PARAMETER Certificate
        The X509Certificate2 to read the SKI from.

    .OUTPUTS
        [string]. Uppercase hex string (no separators), or $null when the extension is absent.

    .EXAMPLE
        Get-CertificateSKI -Certificate $cert

    .EXAMPLE
        $ski = Get-CertificateSKI $cert
        if ($ski) { "SKI=$ski" } else { "no SKI extension" }

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-04-26 - Loïc Ade
            - Initial release
            - Uses the strongly typed X509SubjectKeyIdentifierExtension when available
            - Falls back to ASN.1 OCTET STRING parsing via Get-AsnLength
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $ext = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.14" } | Select-Object -First 1
    if (-not $ext) { return $null }
    if ($ext -is [System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]) {
        return $ext.SubjectKeyIdentifier.ToUpper()
    }
    $b = $ext.RawData
    if ($b.Length -lt 2 -or $b[0] -ne 0x04) { return $null }
    $h = Get-AsnLength -Data $b -Index 1
    $sb = New-Object System.Text.StringBuilder
    for ($i = 0; $i -lt $h.Length; $i++) {
        [void]$sb.Append($b[$h.Offset + $i].ToString("X2"))
    }
    return $sb.ToString()
}
