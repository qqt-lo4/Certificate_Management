function New-MenuItem {
    <#
    .SYNOPSIS
        Creates an executable menu item that runs a scriptblock when selected.

    .DESCRIPTION
        Constructs a menu item object that executes a scriptblock action. Supports
        keyboard shortcuts, custom colors, recommended item marking, and character
        underlining for visual cues.

    .PARAMETER Text
        Menu item text. Mandatory. Alias: Action

    .PARAMETER Content
        Scriptblock to execute when item is selected. Mandatory. Alias: Scriptblock

    .PARAMETER Keyboard
        Keyboard shortcut key. Alias: Item

    .PARAMETER BackgroundColor/ForegroundColor
        Button colors when not focused. Default: console colors.

    .PARAMETER FocusedBackgroundColor/FocusedForegroundColor
        Button colors when focused. Default: inverted console colors.

    .PARAMETER Underline
        Character position to underline. Default: -1 (none).

    .PARAMETER Recommended
        Mark this item as recommended (initially focused).

    .EXAMPLE
        New-MenuItem -Text "Configure Settings" -Content { Set-Config } -Recommended

    .NOTES
        Author: Loïc Ade
        Version: 1.1.0

        CHANGELOG:

        Version 1.1.0 - 2026-04-04 - Loïc Ade
            - Added theme support via Get-CLIDialogTheme for default colors

        Version 1.0.0 - 2025-11-22 - Loïc Ade
            - Initial release
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [Alias("Action")]
        [string]$Text,
        [Parameter(Mandatory, Position = 1)]
        [Alias("Scriptblock")]
        [scriptblock]$Content,
        [Parameter(Position = 2)]
        [Alias("Item")]
        [System.ConsoleKey]$Keyboard,
        [System.ConsoleColor]$BackgroundColor = (Get-CLIDialogTheme "BackgroundColor"),
        [System.ConsoleColor]$ForegroundColor = (Get-CLIDialogTheme "ForegroundColor"),
        [System.ConsoleColor]$FocusedBackgroundColor = (Get-CLIDialogTheme "FocusedBackgroundColor"),
        [System.ConsoleColor]$FocusedForegroundColor = (Get-CLIDialogTheme "FocusedForegroundColor"),
        [int]$Underline = -1,
        [switch]$Recommended
    )
    $sText = $Text
    if ($Underline -ge 0) {
        if ($Underline -ge $Text.Length) {
            throw [System.ArgumentOutOfRangeException] "Can't underline a character greater than string length"
        }
    }
    $hResult = @{
        Text = $sText
        Type = "menuitem"
        Content = $Content
        Keyboard = $Keyboard
        BackgroundColor = $BackgroundColor
        ForegroundColor = $ForegroundColor
        FocusedBackgroundColor = $FocusedBackgroundColor
        FocusedForegroundColor = $FocusedForegroundColor
        Recommended = $Recommended
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "ConvertToButton" -Value {
        Param(
            [bool]$AddNewLine = $true
        )
        $hNewCLIButtonArgs = @{
            Text = $this.Text
            BackgroundColor = $this.BackgroundColor
            ForegroundColor = $this.ForegroundColor
            FocusedBackgroundColor = $this.FocusedBackgroundColor
            FocusedForegroundColor = $this.FocusedForegroundColor
            Object = $this
            AddNewLine = $AddNewLine
        }
        if ($this.Keyboard) { $hNewCLIButtonArgs.Keyboard = $this.Keyboard }
        return New-CLIDialogButton @hNewCLIButtonArgs
    }

    $hResult.psobject.TypeNames.Insert(0, "MenuItem")

    return $hResult
}
