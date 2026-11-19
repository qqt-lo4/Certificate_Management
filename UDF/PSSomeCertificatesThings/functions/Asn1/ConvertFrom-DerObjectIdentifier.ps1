function ConvertFrom-DerObjectIdentifier {
    <#
    .SYNOPSIS
        Converts a DER OBJECT IDENTIFIER element into dotted-decimal notation.

    .PARAMETER Data
        DER byte array containing the OID element.

    .PARAMETER Element
        Element returned by Read-DerElement.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [byte[]]$Data,
        [Parameter(Mandatory)]
        [object]$Element
    )
    if ($Element.Tag -ne 0x06 -or $Element.Length -eq 0) { throw 'Invalid DER object identifier.' }
    $aValues = [System.Collections.Generic.List[long]]::new()
    $iFirst = [int]$Data[$Element.ContentStart]
    $aValues.Add([Math]::Min(2, [Math]::Floor($iFirst / 40)))
    $aValues.Add($iFirst - ($aValues[0] * 40))
    $iValue = [System.Numerics.BigInteger]::Zero
    for ($iByte = $Element.ContentStart + 1; $iByte -lt $Element.End; $iByte++) {
        $iCurrent = [int]$Data[$iByte]
        $iValue = ($iValue * 128) + ($iCurrent -band 0x7f)
        if ($iValue -gt [long]::MaxValue) { throw 'Object identifier component is too large.' }
        if (($iCurrent -band 0x80) -eq 0) {
            $aValues.Add([long]$iValue)
            $iValue = [System.Numerics.BigInteger]::Zero
        }
    }
    if (($Data[$Element.End - 1] -band 0x80) -ne 0) { throw 'Truncated object identifier.' }
    return $aValues -join '.'
}