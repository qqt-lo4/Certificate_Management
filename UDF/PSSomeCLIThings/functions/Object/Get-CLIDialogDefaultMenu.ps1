function Get-CLIDialogDefaultMenu {
    <#
    .SYNOPSIS
        Returns the default footer menu provider registered for the dialog engine.

    .DESCRIPTION
        Reads back the scriptblock previously registered with Set-CLIDialogDefaultMenu.
        The object dialog engine (Get-CLIDialogObject) calls this to obtain the
        default footer menu provider and executes it when no explicit menu override
        is supplied. Returns $null when no provider has been registered, in which
        case the engine simply renders no default footer menu.

    .OUTPUTS
        [scriptblock] or $null.

    .EXAMPLE
        $f = Get-CLIDialogDefaultMenu
        if ($f) { $rows += & $f }

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-06-14 - Loïc Ade
            - Initial release. Counterpart of Set-CLIDialogDefaultMenu.
    #>
    return $Global:CLIDialogDefaultMenu
}
