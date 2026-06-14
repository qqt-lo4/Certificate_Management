function Set-CLIDialogDefaultMenu {
    <#
    .SYNOPSIS
        Registers the default footer menu used by the object dialog engine.

    .DESCRIPTION
        Stores a scriptblock in the global CLIDialogDefaultMenu variable. The object
        dialog engine (Get-CLIDialogObject) executes this scriptblock to append a
        default footer menu (typically navigation buttons such as Back / Search /
        Exit) whenever no explicit -OtherMenuItems override is supplied.

        This is an inversion-of-control hook: it keeps the CLI module free of any
        project-specific menu. The hosting project registers its own menu once at
        startup, e.g.:

            Set-CLIDialogDefaultMenu { Get-GoTo_ProjectMenu }

        It mirrors the Set-CLIDialogTheme / Get-CLIDialogTheme mechanism used for
        colors: a single global slot, written by Set-, read lazily by Get-.

    .PARAMETER MenuProvider
        A scriptblock that returns the dialog rows of the default footer menu when
        invoked. It is called with no arguments by the engine. Returning an empty
        value is allowed (no footer menu is appended).

    .EXAMPLE
        Set-CLIDialogDefaultMenu { Get-GoTo_ProjectMenu }
        # The engine now appends the project navigation menu to every object dialog.

    .EXAMPLE
        Set-CLIDialogDefaultMenu {
            New-CLIDialogObjectsRow -Header "Go to" -Row @(
                New-CLIDialogButton -Back -Text "Back" -Underline 0 -Keyboard B
                New-CLIDialogButton -Exit -Text "Exit" -Underline 0 -Keyboard E
            )
        }

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-06-14 - Loïc Ade
            - Initial release. Extracted from the Hotline_tool object dialog
              engine to decouple Get-CLIDialogObject from the project-specific
              Get-GoTo_ProjectMenu.
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [scriptblock]$MenuProvider
    )
    $Global:CLIDialogDefaultMenu = $MenuProvider
}
