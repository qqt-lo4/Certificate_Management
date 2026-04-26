function Get-AsnLength {
    <#
    .SYNOPSIS
        Decodes an ASN.1 / DER length octet sequence

    .DESCRIPTION
        Reads the ASN.1 / DER length encoding starting at the given index inside a byte
        array and returns both the decoded length and the offset of the first content byte.
        Supports the short form (length < 128 in a single byte) and the long form
        (high bit set on the first byte indicates the number of following length bytes,
        big-endian).

        Used to walk DER-encoded structures such as X.509 extensions when no high level
        type is available (for instance the AuthorityKeyIdentifier extension).

    .PARAMETER Data
        The byte array containing the DER-encoded value.

    .PARAMETER Index
        Zero-based index of the first length byte in Data.

    .OUTPUTS
        [hashtable]. @{ Length = <decoded content length> ; Offset = <index of the first content byte> }

    .EXAMPLE
        $bytes = $ext.RawData
        $h = Get-AsnLength -Data $bytes -Index 1   # right after the outer SEQUENCE tag at index 0
        $contentEnd = $h.Offset + $h.Length

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-04-26 - Loïc Ade
            - Initial release
            - Decodes short and long-form ASN.1 length octets
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [byte[]]$Data,
        [Parameter(Mandatory, Position = 1)]
        [int]$Index
    )
    $first = $Data[$Index]
    if (($first -band 0x80) -eq 0) {
        return @{ Length = [int]$first; Offset = $Index + 1 }
    }
    $iLenBytes = $first -band 0x7F
    $iLen = 0
    for ($i = 0; $i -lt $iLenBytes; $i++) {
        $iLen = ($iLen -shl 8) -bor $Data[$Index + 1 + $i]
    }
    return @{ Length = $iLen; Offset = $Index + 1 + $iLenBytes }
}
