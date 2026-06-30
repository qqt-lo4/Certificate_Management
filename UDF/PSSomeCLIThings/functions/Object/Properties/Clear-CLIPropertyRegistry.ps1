function Clear-CLIPropertyRegistry {
    <#
    .SYNOPSIS
        Empties the global object-property registry.

    .DESCRIPTION
        Resets $Global:CLIPropertyRegistry to an empty hashtable. The registry is the
        declarative store consumed by Get-CLIObjectPropertyList to build the property
        list of an object dialog view (see Register-CLIObjectProperty). Call this before
        re-registering (e.g. at startup, or in tests) so a reload starts from a clean
        state.

    .OUTPUTS
        None.

    .EXAMPLE
        Clear-CLIPropertyRegistry

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-06-17 - Loïc Ade
            - Initial release. Companion of the menu registry's Clear-CLIMenuRegistry,
              for the object-property registry.
    #>
    Param()
    $Global:CLIPropertyRegistry = @{}
}
