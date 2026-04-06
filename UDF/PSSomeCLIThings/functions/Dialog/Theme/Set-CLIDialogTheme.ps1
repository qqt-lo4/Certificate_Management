function Set-CLIDialogTheme {
    <#
    .SYNOPSIS
        Sets the global CLI dialog theme.

    .DESCRIPTION
        Creates or updates the global CLIDialogTheme variable with centralized color
        definitions for all CLI dialog components. Each parameter has a default value
        matching the standard theme. Calling this function sets all properties at once.

    .PARAMETER ForegroundColor
        Default foreground color for text and buttons.

    .PARAMETER BackgroundColor
        Default background color.

    .PARAMETER HeaderForegroundColor
        Foreground color for headers (textbox, property, row labels).

    .PARAMETER HeaderBackgroundColor
        Background color for headers.

    .PARAMETER FocusedHeaderForegroundColor
        Foreground color for focused headers.

    .PARAMETER FocusedHeaderBackgroundColor
        Background color for focused headers.

    .PARAMETER FocusedForegroundColor
        Foreground color for focused controls (buttons, checkboxes, radio buttons, menu items).

    .PARAMETER FocusedBackgroundColor
        Background color for focused controls.

    .PARAMETER SelectionForegroundColor
        Foreground color for selected text in textboxes.

    .PARAMETER SelectionBackgroundColor
        Background color for selected text in textboxes.

    .PARAMETER SelectionCursorBackgroundColor
        Background color for the cursor character within a text selection.

    .PARAMETER ValidationErrorColor
        Color for headers when validation fails.

    .PARAMETER MatchTextForegroundColor
        Foreground color for pattern-matched text in properties.

    .PARAMETER MatchTextBackgroundColor
        Background color for pattern-matched text in properties.

    .PARAMETER SeparatorColor
        Foreground color for separator lines.

    .EXAMPLE
        Set-CLIDialogTheme
        # Initializes the theme with default values

    .EXAMPLE
        Set-CLIDialogTheme -HeaderForegroundColor Cyan -SelectionBackgroundColor DarkBlue
        # Sets all properties to defaults, with Cyan headers and DarkBlue selection

    .NOTES
        Author: Loïc Ade
        Version: 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-04-03 - Loïc Ade
            - Initial release
    #>
    Param(
        [System.ConsoleColor]$ForegroundColor = (Get-Host).UI.RawUI.ForegroundColor,
        [System.ConsoleColor]$BackgroundColor = (Get-Host).UI.RawUI.BackgroundColor,
        [System.ConsoleColor]$HeaderForegroundColor = [System.ConsoleColor]::Green,
        [System.ConsoleColor]$HeaderBackgroundColor = (Get-Host).UI.RawUI.BackgroundColor,
        [System.ConsoleColor]$FocusedHeaderForegroundColor = [System.ConsoleColor]::Blue,
        [System.ConsoleColor]$FocusedHeaderBackgroundColor = (Get-Host).UI.RawUI.BackgroundColor,
        [System.ConsoleColor]$FocusedForegroundColor = (Get-Host).UI.RawUI.BackgroundColor,
        [System.ConsoleColor]$FocusedBackgroundColor = (Get-Host).UI.RawUI.ForegroundColor,
        [System.ConsoleColor]$SelectionForegroundColor = (Get-Host).UI.RawUI.BackgroundColor,
        [System.ConsoleColor]$SelectionBackgroundColor = [System.ConsoleColor]::DarkCyan,
        [System.ConsoleColor]$SelectionCursorBackgroundColor = [System.ConsoleColor]::Blue,
        [System.ConsoleColor]$ValidationErrorColor = [System.ConsoleColor]::Red,
        [System.ConsoleColor]$MatchTextForegroundColor = [System.ConsoleColor]::Blue,
        [System.ConsoleColor]$MatchTextBackgroundColor = (Get-Host).UI.RawUI.BackgroundColor,
        [System.ConsoleColor]$TableHeaderForegroundColor = [System.ConsoleColor]::Green,
        [System.ConsoleColor]$HintColor = [System.ConsoleColor]::Gray,
        [System.ConsoleColor]$WarningColor = [System.ConsoleColor]::Yellow,
        [System.ConsoleColor]$ErrorColor = [System.ConsoleColor]::Red,
        [System.ConsoleColor]$OverflowIndicatorColor = [System.ConsoleColor]::DarkYellow,
        [string]$OverflowIndicatorLeft = [string][char]0x25C4,
        [string]$OverflowIndicatorRight = [string][char]0x25BA,
        [System.ConsoleColor]$SeparatorColor = [System.ConsoleColor]::Blue
    )
    if (-not ($Global:CLIDialogTheme -is [hashtable])) {
        $Global:CLIDialogTheme = @{}
    }
    $Global:CLIDialogTheme.ForegroundColor                = $ForegroundColor
    $Global:CLIDialogTheme.BackgroundColor                = $BackgroundColor
    $Global:CLIDialogTheme.HeaderForegroundColor          = $HeaderForegroundColor
    $Global:CLIDialogTheme.HeaderBackgroundColor          = $HeaderBackgroundColor
    $Global:CLIDialogTheme.FocusedHeaderForegroundColor   = $FocusedHeaderForegroundColor
    $Global:CLIDialogTheme.FocusedHeaderBackgroundColor   = $FocusedHeaderBackgroundColor
    $Global:CLIDialogTheme.FocusedForegroundColor         = $FocusedForegroundColor
    $Global:CLIDialogTheme.FocusedBackgroundColor         = $FocusedBackgroundColor
    $Global:CLIDialogTheme.SelectionForegroundColor       = $SelectionForegroundColor
    $Global:CLIDialogTheme.SelectionBackgroundColor       = $SelectionBackgroundColor
    $Global:CLIDialogTheme.SelectionCursorBackgroundColor = $SelectionCursorBackgroundColor
    $Global:CLIDialogTheme.ValidationErrorColor           = $ValidationErrorColor
    $Global:CLIDialogTheme.MatchTextForegroundColor       = $MatchTextForegroundColor
    $Global:CLIDialogTheme.MatchTextBackgroundColor       = $MatchTextBackgroundColor
    $Global:CLIDialogTheme.TableHeaderForegroundColor    = $TableHeaderForegroundColor
    $Global:CLIDialogTheme.HintColor                     = $HintColor
    $Global:CLIDialogTheme.WarningColor                  = $WarningColor
    $Global:CLIDialogTheme.ErrorColor                    = $ErrorColor
    $Global:CLIDialogTheme.OverflowIndicatorColor          = $OverflowIndicatorColor
    $Global:CLIDialogTheme.OverflowIndicatorLeft           = $OverflowIndicatorLeft
    $Global:CLIDialogTheme.OverflowIndicatorRight          = $OverflowIndicatorRight
    $Global:CLIDialogTheme.SeparatorColor                 = $SeparatorColor
}
