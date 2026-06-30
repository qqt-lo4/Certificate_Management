function Register-CLIMenuTypeAlias {
    <#
    .SYNOPSIS
        Declares that a concrete menu type also counts as a more generic type.

    .DESCRIPTION
        Records an "IS-A" correspondence in $Global:CLIMenuTypeAliases, used by
        Resolve-CLIMenuType to extend an object's native type hierarchy with abstract
        type tokens that are not present in its PSTypeNames.

        This lets a module register menu buttons against a generic token (e.g.
        "Computer") while the module that owns the concrete type declares the
        membership (e.g. "ADComputer" IS-A "Computer"). Neither module needs to know
        about the other. The generic tokens are appended after the native ones, so
        their buttons render after the type-specific buttons.

    .PARAMETER Type
        The concrete type token (compact form, spaces removed), e.g. "ADComputer".

    .PARAMETER IsAlso
        The more generic type token it also belongs to, e.g. "Computer".

    .EXAMPLE
        Register-CLIMenuTypeAlias -Type "ADComputer" -IsAlso "Computer"

    .EXAMPLE
        Register-CLIMenuTypeAlias -Type "EPOSystem" -IsAlso "Computer"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-06-14 - Loïc Ade
            - Initial release. Type correspondence registry for menu resolution.
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Type,
        [Parameter(Mandatory, Position = 1)]
        [string]$IsAlso
    )

    if ($Global:CLIMenuTypeAliases -isnot [hashtable]) {
        $Global:CLIMenuTypeAliases = @{}
    }

    $sType   = $Type.Replace(' ', '')
    $sIsAlso = $IsAlso.Replace(' ', '')

    if (-not $Global:CLIMenuTypeAliases.ContainsKey($sType)) {
        $Global:CLIMenuTypeAliases[$sType] = @()
    }
    if ($sIsAlso -notin $Global:CLIMenuTypeAliases[$sType]) {
        $Global:CLIMenuTypeAliases[$sType] += $sIsAlso
    }
}
