function Get-CLIDialogTheme {
    <#
    .SYNOPSIS
        Retrieves the current CLI dialog theme or a specific theme property.

    .DESCRIPTION
        Returns the current CLI dialog theme hashtable, or the value of a specific theme
        property when the Key parameter is specified. Used by CLI dialog components
        to resolve their default color values from the centralized theme.

        If no theme has been set via Set-CLIDialogTheme, initializes the default theme
        on first call.

    .PARAMETER Key
        The name of a specific theme property to retrieve. If specified, returns
        only the value of that property. If the key does not exist, throws an error.

    .OUTPUTS
        [hashtable] when called without Key parameter.
        [System.ConsoleColor] when called with Key parameter.

    .EXAMPLE
        $theme = Get-CLIDialogTheme
        # Returns the full theme hashtable

    .EXAMPLE
        $color = Get-CLIDialogTheme -Key "HeaderForegroundColor"
        # Returns [System.ConsoleColor]::Green (default)

    .EXAMPLE
        # Usage in a component parameter default:
        # [System.ConsoleColor]$HeaderForegroundColor = (Get-CLIDialogTheme -Key "HeaderForegroundColor")

    .NOTES
        Author: Loïc Ade
        Version: 1.0.0

        THEME PROPERTIES:
        - ForegroundColor              : Default foreground color for text and buttons
        - BackgroundColor              : Default background color
        - HeaderForegroundColor        : Foreground color for headers (textbox, property, row labels)
        - HeaderBackgroundColor        : Background color for headers
        - FocusedHeaderForegroundColor : Foreground color for focused headers
        - FocusedHeaderBackgroundColor : Background color for focused headers
        - FocusedForegroundColor       : Foreground color for focused controls (buttons, checkboxes, radio buttons, menu items)
        - FocusedBackgroundColor       : Background color for focused controls
        - SelectionForegroundColor     : Foreground color for selected text in textboxes
        - SelectionBackgroundColor     : Background color for selected text in textboxes
        - SelectionCursorBackgroundColor : Background color for the cursor character within a text selection
        - ValidationErrorColor         : Color for headers when validation fails
        - MatchTextForegroundColor     : Foreground color for pattern-matched text in properties
        - MatchTextBackgroundColor     : Background color for pattern-matched text in properties
        - TableHeaderForegroundColor   : Foreground color for table column headers
        - HintColor                    : Color for hint/help text
        - WarningColor                 : Color for warning messages
        - ErrorColor                   : Color for error messages
        - OverflowIndicatorColor       : Color for overflow indicators (◄/►)
        - OverflowIndicatorLeft        : Left overflow indicator character (default ◄)
        - OverflowIndicatorRight       : Right overflow indicator character (default ►)
        - SeparatorColor               : Foreground color for separator lines

        CHANGELOG:

        Version 1.0.0 - 2026-04-03 - Loïc Ade
            - Initial release
    #>
    Param(
        [Parameter(Position = 0)]
        [string]$Key
    )
    if (-not ($Global:CLIDialogTheme -is [hashtable])) {
        Set-CLIDialogTheme
    }
    if ($Key) {
        if (-not $Global:CLIDialogTheme.ContainsKey($Key)) {
            throw "Unknown theme property: $Key"
        }
        return $Global:CLIDialogTheme[$Key]
    }
    return $Global:CLIDialogTheme
}
