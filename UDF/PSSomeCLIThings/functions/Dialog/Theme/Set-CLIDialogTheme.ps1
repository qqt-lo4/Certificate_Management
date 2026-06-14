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

    .PARAMETER HighlightColor
        Single semantic "accent" color. Cascades as the default for every
        key that shares the highlight semantic - currently FocusedHeader-
        ForegroundColor, MatchTextForegroundColor, and SeparatorColor.
        Setting -HighlightColor without explicitly overriding any of
        those three flips them all at once. Explicit per-key overrides
        still win:
            Set-CLIDialogTheme -HighlightColor Cyan
              -> all three cascade keys = Cyan
            Set-CLIDialogTheme -HighlightColor Cyan -SeparatorColor Magenta
              -> SeparatorColor = Magenta, the other two = Cyan

    .PARAMETER FocusedHeaderForegroundColor
        Foreground color for focused headers. Defaults to HighlightColor.

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
        Defaults to HighlightColor.

    .PARAMETER MatchTextBackgroundColor
        Background color for pattern-matched text in properties.

    .PARAMETER SeparatorColor
        Foreground color for separator lines. Defaults to HighlightColor.

    .EXAMPLE
        Set-CLIDialogTheme
        # Initializes the theme with default values

    .EXAMPLE
        Set-CLIDialogTheme -HeaderForegroundColor Cyan -SelectionBackgroundColor DarkBlue
        # Sets all properties to defaults, with Cyan headers and DarkBlue selection

    .EXAMPLE
        Set-CLIDialogTheme -HighlightColor Cyan
        # Cascades Cyan to FocusedHeaderForegroundColor,
        # MatchTextForegroundColor, and SeparatorColor in one shot.

    .NOTES
        Author: Loïc Ade
        Version: 1.1.0

        CHANGELOG:

        Version 1.1.0 - 2026-06-04 - Loïc Ade
            - Add HighlightColor as a semantic "accent" knob that
              cascades to FocusedHeaderForegroundColor,
              MatchTextForegroundColor, and SeparatorColor when
              those keys aren't explicitly overridden. Explicit
              per-key overrides still win.

        Version 1.0.0 - 2026-04-03 - Loïc Ade
            - Initial release
    #>
    Param(
        [System.ConsoleColor]$ForegroundColor = (Get-Host).UI.RawUI.ForegroundColor,
        [System.ConsoleColor]$BackgroundColor = (Get-Host).UI.RawUI.BackgroundColor,
        [System.ConsoleColor]$HeaderForegroundColor = [System.ConsoleColor]::Green,
        [System.ConsoleColor]$HeaderBackgroundColor = (Get-Host).UI.RawUI.BackgroundColor,
        [System.ConsoleColor]$HighlightColor = [System.ConsoleColor]::Blue,
        # The three cascade targets below have NO static default. Their
        # value is resolved after Param binding from $HighlightColor
        # when the caller didn't explicitly pass them - see the cascade
        # block right after Param().
        [System.ConsoleColor]$FocusedHeaderForegroundColor,
        [System.ConsoleColor]$FocusedHeaderBackgroundColor = (Get-Host).UI.RawUI.BackgroundColor,
        [System.ConsoleColor]$FocusedForegroundColor = (Get-Host).UI.RawUI.BackgroundColor,
        [System.ConsoleColor]$FocusedBackgroundColor = (Get-Host).UI.RawUI.ForegroundColor,
        [System.ConsoleColor]$SelectionForegroundColor = (Get-Host).UI.RawUI.BackgroundColor,
        [System.ConsoleColor]$SelectionBackgroundColor = [System.ConsoleColor]::DarkCyan,
        [System.ConsoleColor]$SelectionCursorBackgroundColor = [System.ConsoleColor]::Blue,
        [System.ConsoleColor]$ValidationErrorColor = [System.ConsoleColor]::Red,
        [System.ConsoleColor]$MatchTextForegroundColor,
        [System.ConsoleColor]$MatchTextBackgroundColor = (Get-Host).UI.RawUI.BackgroundColor,
        [System.ConsoleColor]$TableHeaderForegroundColor = [System.ConsoleColor]::Green,
        [System.ConsoleColor]$HintColor = [System.ConsoleColor]::Gray,
        [System.ConsoleColor]$WarningColor = [System.ConsoleColor]::Yellow,
        [System.ConsoleColor]$ErrorColor = [System.ConsoleColor]::Red,
        [System.ConsoleColor]$OverflowIndicatorColor = [System.ConsoleColor]::DarkYellow,
        [string]$OverflowIndicatorLeft = [string][char]0x25C4,
        [string]$OverflowIndicatorRight = [string][char]0x25BA,
        [System.ConsoleColor]$SeparatorColor
    )

    # HighlightColor cascade: fill in the unset cascade targets so a
    # single -HighlightColor knob flips every "accent" surface.
    # Per-key overrides take precedence because we only touch the
    # target when its name isn't in $PSBoundParameters.
    foreach ($sCascadeKey in 'FocusedHeaderForegroundColor', 'MatchTextForegroundColor', 'SeparatorColor') {
        if (-not $PSBoundParameters.ContainsKey($sCascadeKey)) {
            Set-Variable -Name $sCascadeKey -Value $HighlightColor
        }
    }

    if (-not ($Global:CLIDialogTheme -is [hashtable])) {
        $Global:CLIDialogTheme = @{}
    }
    $Global:CLIDialogTheme.HighlightColor                 = $HighlightColor
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
    $Global:CLIDialogTheme.TableHeaderForegroundColor     = $TableHeaderForegroundColor
    $Global:CLIDialogTheme.HintColor                      = $HintColor
    $Global:CLIDialogTheme.WarningColor                   = $WarningColor
    $Global:CLIDialogTheme.ErrorColor                     = $ErrorColor
    $Global:CLIDialogTheme.OverflowIndicatorColor         = $OverflowIndicatorColor
    $Global:CLIDialogTheme.OverflowIndicatorLeft          = $OverflowIndicatorLeft
    $Global:CLIDialogTheme.OverflowIndicatorRight         = $OverflowIndicatorRight
    $Global:CLIDialogTheme.SeparatorColor                 = $SeparatorColor
}
