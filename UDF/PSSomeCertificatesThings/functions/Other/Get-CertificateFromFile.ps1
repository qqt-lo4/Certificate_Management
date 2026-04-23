function Get-CertificateFromFile {
    <#
    .SYNOPSIS
        Loads an X.509 certificate from a file path

    .DESCRIPTION
        Loads a certificate from a file on disk and returns it as
        System.Security.Cryptography.X509Certificates.X509Certificate2.
        The input path is trimmed and, if the value is wrapped in matching single or double
        quotes (common when a path is copy-pasted from Windows Explorer), the surrounding
        quotes are stripped before the file is read.

        Supports any format handled by X509Certificate2 (PEM, DER / .cer, .crt, .p7b, .pfx, ...).
        For PFX with a password, use the standard X509Certificate2 constructor directly.

    .PARAMETER Path
        Path to the certificate file. Surrounding single or double quotes are tolerated and
        removed automatically.

    .OUTPUTS
        [System.Security.Cryptography.X509Certificates.X509Certificate2].

    .EXAMPLE
        Get-CertificateFromFile -Path 'C:\Certs\server.cer'

    .EXAMPLE
        Get-CertificateFromFile -Path '"C:\Certs\with space.cer"'

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-04-22 - Loïc Ade
            - Initial release
            - Loads a certificate from a file into an X509Certificate2
            - Tolerates surrounding single or double quotes on the path
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Path
    )
    $sPath = $Path.Trim()
    if ($sPath.Length -ge 2 -and (
        ($sPath.StartsWith('"') -and $sPath.EndsWith('"')) -or
        ($sPath.StartsWith("'") -and $sPath.EndsWith("'"))
    )) {
        $sPath = $sPath.Substring(1, $sPath.Length - 2)
    }
    if (-not (Test-Path -LiteralPath $sPath -PathType Leaf)) {
        throw "Certificate file not found: $sPath"
    }
    return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $sPath
}
