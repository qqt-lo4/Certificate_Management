function Test-StringIsMacAddress {
    <#
    .SYNOPSIS
        Tests if a string is a valid MAC address

    .DESCRIPTION
        Validates whether a string matches common MAC address formats
        (XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, XXXX-XXXX-XXXX, XXXXXX-XXXXXX, XXXXXXXXXXXX).

    .PARAMETER InputString
        The string to test.

    .OUTPUTS
        [Hashtable] or $false. Contains Type, Category, Value, InputString if valid.

    .EXAMPLE
        Test-StringIsMacAddress "AA:BB:CC:DD:EE:FF"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

    Param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string]$InputString
    )
    $bResult = ($InputString -match "^([0-9a-fA-F]{2}(:|-)){5}[0-9a-fA-F]{2}$") -or `
           ($InputString -match "^([0-9a-fA-F]{4}-){2}[0-9a-fA-F]{4}$") -or `
           ($InputString -match "^[0-9a-fA-F]{6}-[0-9a-fA-F]{6}$") -or `
           ($InputString -match "^[0-9a-fA-F]{12}$")
    if ($bResult) {
        $hResult = Select-String -InputObject $InputString -Pattern "[a-fA-F0-9]" -AllMatches | Convert-MatchInfoToHashtable
        return @{
            Type = "macaddress"
            Category = "MacAddress"
            Value = $hResult[0] -join ""
            InputString = $InputString
        }
    } else {
        return $false
    }
}