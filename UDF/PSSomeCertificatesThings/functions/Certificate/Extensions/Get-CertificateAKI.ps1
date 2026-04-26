function Get-CertificateAKI {
    <#
    .SYNOPSIS
        Returns the AuthorityKeyIdentifier (keyIdentifier field) of an X.509 certificate as an uppercase hex string

    .DESCRIPTION
        Reads the AuthorityKeyIdentifier extension (OID 2.5.29.35) from the certificate and
        extracts the keyIdentifier component. The extension is DER-encoded as

            AuthorityKeyIdentifier ::= SEQUENCE {
                keyIdentifier             [0] OCTET STRING        OPTIONAL,
                authorityCertIssuer       [1] GeneralNames        OPTIONAL,
                authorityCertSerialNumber [2] INTEGER             OPTIONAL
            }

        Only the keyIdentifier ([0] context-specific) is returned, since it is the
        component used to chain a certificate to its issuer's SubjectKeyIdentifier.

    .PARAMETER Certificate
        The X509Certificate2 to read the AKI from.

    .OUTPUTS
        [string]. Uppercase hex string (no separators), or $null when the extension is
        absent or carries no keyIdentifier component.

    .EXAMPLE
        Get-CertificateAKI -Certificate $cert

    .EXAMPLE
        # Match a certificate against its parent in a set:
        $aki = Get-CertificateAKI $child
        $parent = $candidates | Where-Object { (Get-CertificateSKI $_) -eq $aki }

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-04-26 - Loïc Ade
            - Initial release
            - DER-walks the AuthorityKeyIdentifier SEQUENCE looking for the [0] tag
            - Uses Get-AsnLength to handle short and long-form length octets
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $ext = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.35" } | Select-Object -First 1
    if (-not $ext) { return $null }
    $b = $ext.RawData
    if ($b.Length -lt 2 -or $b[0] -ne 0x30) { return $null }
    $hSeq = Get-AsnLength -Data $b -Index 1
    $iEnd = $hSeq.Offset + $hSeq.Length
    $idx = $hSeq.Offset
    while ($idx -lt $iEnd) {
        $tag = $b[$idx]
        $hLen = Get-AsnLength -Data $b -Index ($idx + 1)
        if ($tag -eq 0x80) {
            $sb = New-Object System.Text.StringBuilder
            for ($i = 0; $i -lt $hLen.Length; $i++) {
                [void]$sb.Append($b[$hLen.Offset + $i].ToString("X2"))
            }
            return $sb.ToString()
        }
        $idx = $hLen.Offset + $hLen.Length
    }
    return $null
}
