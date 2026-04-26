function ConvertTo-PEMCertificate {
    <#
    .SYNOPSIS
        Converts an X509Certificate2 into its PEM textual representation

    .DESCRIPTION
        Serializes the certificate's RawData (DER) as Base64 with line breaks every
        64 characters and wraps it between the standard PEM BEGIN / END CERTIFICATE
        delimiters. The trailing line break after END CERTIFICATE makes the output
        directly concatenable when assembling a chain file.

    .PARAMETER Certificate
        The X509Certificate2 to serialize.

    .OUTPUTS
        [string]. The PEM block, terminated by a newline.

    .EXAMPLE
        ConvertTo-PEMCertificate -Certificate $cert | Out-File chain.pem -Encoding ascii

    .EXAMPLE
        # Concatenate several certs into a single chain file:
        ($chain | ForEach-Object { ConvertTo-PEMCertificate $_ }) -join "" | Out-File chain.pem -Encoding ascii

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-04-26 - Loïc Ade
            - Initial release
            - Outputs LF line endings inside the PEM block; callers requiring CRLF
              should write the file with the appropriate encoding/line-ending option
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $sB64 = [Convert]::ToBase64String($Certificate.RawData, [System.Base64FormattingOptions]::InsertLineBreaks)
    return "-----BEGIN CERTIFICATE-----`n$sB64`n-----END CERTIFICATE-----`n"
}
