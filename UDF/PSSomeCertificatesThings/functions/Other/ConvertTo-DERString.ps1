function ConvertTo-DERString {
    <#
    .SYNOPSIS
        Converts byte array to DER string format

    .DESCRIPTION
        Converts a byte array to DER (Distinguished Encoding Rules) string representation
        by converting bytes to hexadecimal and then to characters.

    .PARAMETER bytes
        Byte array to convert to DER string.

    .OUTPUTS
        [String]. DER-encoded string representation.

    .EXAMPLE
        $derString = ConvertTo-DERString -bytes $certBytes

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [byte[]]$bytes
    )

    $StringBuilder = New-Object System.Text.StringBuilder
    $HexBytes = $bytes | ForEach-Object { "{0:X2}" -f $_ }

    for ($i = 0; $i -lt $HexBytes.Count; $i += 2) {
        $LowByte  = $HexBytes[$i + 1]
        $HighByte = $HexBytes[$i]
        $HexValue = "0x$($LowByte)$($HighByte)"
        [void]$StringBuilder.Append([char][uint16]$HexValue)
    }

    $StringBuilder.ToString()
}
