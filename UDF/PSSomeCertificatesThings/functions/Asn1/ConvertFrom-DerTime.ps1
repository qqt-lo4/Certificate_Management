function ConvertFrom-DerTime {
    <#
    .SYNOPSIS
        Converts a DER UTCTime or GeneralizedTime element into a UTC DateTime.

    .PARAMETER Data
        DER byte array containing the time element.

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
    $sText = [System.Text.Encoding]::ASCII.GetString($Data, $Element.ContentStart, $Element.Length)
    $sFormat = switch ($Element.Tag) {
        0x17 {
            if ($sText -match '^\d{12}Z$') { "yyMMddHHmmss'Z'" }
            elseif ($sText -match '^\d{10}Z$') { "yyMMddHHmm'Z'" }
            else { throw "Invalid UTCTime '$sText'." }
        }
        0x18 {
            if ($sText -match '^\d{14}Z$') { "yyyyMMddHHmmss'Z'" }
            elseif ($sText -match '^\d{14}\.\d+Z$') { "yyyyMMddHHmmss.FFFFFFF'Z'" }
            else { throw "Invalid GeneralizedTime '$sText'." }
        }
        default { throw 'Unexpected DER time tag.' }
    }
    return [DateTime]::SpecifyKind([DateTime]::ParseExact($sText, $sFormat, [Globalization.CultureInfo]::InvariantCulture), [DateTimeKind]::Utc)
}