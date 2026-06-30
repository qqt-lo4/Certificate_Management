function Clear-CLIMenuRegistry {
    <#
    .SYNOPSIS
        Empties the menu button registry and the type alias registry.

    .DESCRIPTION
        Resets $Global:CLIMenuRegistry and $Global:CLIMenuTypeAliases to empty
        hashtables. Useful for tests and for a full reload of the menu definitions.

    .EXAMPLE
        Clear-CLIMenuRegistry

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-06-14 - Loïc Ade
            - Initial release.
    #>
    Param()
    $Global:CLIMenuRegistry    = @{}
    $Global:CLIMenuTypeAliases = @{}
}
