function Read-DerElement {
    <#
    .SYNOPSIS
        Reads one DER element and returns its tag, content range and encoded bytes.

    .PARAMETER Data
        DER byte array containing the element.

    .PARAMETER Offset
        Zero-based offset of the element tag.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [byte[]]$Data,
        [Parameter(Mandatory)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Offset
    )
    if ($Offset + 2 -gt $Data.Length) { throw 'Truncated DER element.' }
    $iTag = [int]$Data[$Offset]
    $iLengthByte = [int]$Data[$Offset + 1]
    $iLengthOctets = if (($iLengthByte -band 0x80) -eq 0) { 0 } else { $iLengthByte -band 0x7f }
    if ($iLengthOctets -gt 4 -or ($iLengthByte -eq 0x80)) { throw 'Invalid or unsupported DER length.' }
    if ($Offset + 2 + $iLengthOctets -gt $Data.Length) { throw 'Truncated DER length.' }

    $hLength = Get-AsnLength -Data $Data -Index ($Offset + 1)
    if ($hLength.Length -gt [int]::MaxValue) { throw 'DER element is too large.' }
    $iEnd = $hLength.Offset + $hLength.Length
    if ($iEnd -gt $Data.Length) { throw 'DER element exceeds the available data.' }
    [PSCustomObject]@{
        Tag = $iTag
        Start = $Offset
        ContentStart = $hLength.Offset
        Length = $hLength.Length
        End = $iEnd
        Encoded = [byte[]]$Data[$Offset..($iEnd - 1)]
    }
}