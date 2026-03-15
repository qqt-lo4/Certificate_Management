function New-PasswordPolicy {
    <#
    .SYNOPSIS
        Creates a password policy object with validation rules

    .DESCRIPTION
        Builds a password policy object with mandatory, common, and forbidden rules.
        Common rules include numbers, uppercase letters, lowercase letters, and symbols.
        Automatically adds min/max length as mandatory rules.

    .PARAMETER Numbers
        Includes numbers requirement in common rules.

    .PARAMETER Uppercase_Letters
        Includes uppercase letters requirement in common rules.

    .PARAMETER Lowercase_Letters
        Includes lowercase letters requirement in common rules.

    .PARAMETER Symbols
        Includes symbols (non-alphanumeric) requirement in common rules.

    .PARAMETER All
        Includes all common rules (numbers, uppercase, lowercase, symbols).

    .PARAMETER MinimalLength
        Minimum password length. Default is 8.

    .PARAMETER MaximalLength
        Maximum password length. Default is [int]::MaxValue.

    .PARAMETER MandatoryRules
        Hashtable of custom mandatory rules (regex => description).

    .PARAMETER MustRespectCommonRulesCount
        Minimum number of common rules that must be satisfied.

    .PARAMETER ForbiddenRules
        Hashtable of forbidden pattern rules (regex => description).

    .OUTPUTS
        [PSCustomObject]. Object with MandatoryRules, CommonRules, MinCommonRulesCount, and ForbiddenRules properties.

    .EXAMPLE
        New-PasswordPolicy -All -MinimalLength 12

    .EXAMPLE
        New-PasswordPolicy -Numbers -Uppercase_Letters -Lowercase_Letters -MinimalLength 10 -MustRespectCommonRulesCount 2

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(ParameterSetName = "custom")]
        [switch]$Numbers,
        [Parameter(ParameterSetName = "custom")]
        [switch]$Uppercase_Letters,
        [Parameter(ParameterSetName = "custom")]
        [switch]$Lowercase_Letters,
        [Parameter(ParameterSetName = "custom")]
        [switch]$Symbols,
        [Parameter(ParameterSetName = "all")]
        [switch]$All,
        [int]$MinimalLength = 8,
        [int]$MaximalLength = [int]::MaxValue,
        [hashtable]$MandatoryRules,
        [int]$MustRespectCommonRulesCount,
        [hashtable]$ForbiddenRules
    )
    Begin {
        $hMandatoryRules = if ($MandatoryRules) { $MandatoryRules } else { @{} }
        $hForbiddenRules = if ($ForbiddenRules) { $ForbiddenRules } else { @{} }
        $hCommonRules = New-Object System.Collections.Hashtable
    }
    Process {
        # create common rules
        if ($Numbers.IsPresent -or $All.IsPresent) { $hCommonRules."[0-9]+" = "numbers" }
        if ($Uppercase_Letters.IsPresent -or $All.IsPresent) { $hCommonRules."[A-Z]+" = "uppercase letters" }
        if ($Lowercase_Letters.IsPresent -or $All.IsPresent) { $hCommonRules."[a-z]+" = "lowercase letters" }
        if ($Symbols.IsPresent -or $All.IsPresent) { $hCommonRules."[^a-zA-Z0-9]+" = "symbols" }
        if ($MustRespectCommonRulesCount -gt $hCommonRules.Keys.Count) {
            throw [System.ArgumentOutOfRangeException] "Number of mandatory common rules is greater than count of common rules"
        }
        # manage mandatory rules
        $hMandatoryRules += @{
            "^.{$MinimalLength,}$" = "Password below minimal length"
        }
        $hMandatoryRules += @{
            "^.{0,$MaximalLength}$" = "Password above maximum length"
        }
        # build result
        return [PSCustomObject]@{
            MandatoryRules = $hMandatoryRules
            CommonRules = $hCommonRules
            MinCommonRulesCount = $MustRespectCommonRulesCount
            ForbiddenRules = $hForbiddenRules
        }
    }
}
