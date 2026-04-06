function New-CLIDialogText {
    <#
    .SYNOPSIS
        Creates a text display object for CLI dialog interfaces.

    .DESCRIPTION
        This function creates a text display object that can be used as a component in CLI dialogs.
        The object supports static text, dynamic text generation via scriptblock, multi-line text,
        custom colors, and ANSI escape sequences. It includes methods for drawing the text to the
        console and calculating text dimensions.

    .PARAMETER Text
        The text content to display. Can be empty or contain newline characters for multi-line text.
        This parameter is optional and can be used at position 0.

    .PARAMETER BackgroundColor
        The background color for the text. Default is the current console background color.

    .PARAMETER ForegroundColor
        The foreground (text) color. Default is the current console foreground color.

    .PARAMETER AddNewLine
        Switch parameter. If specified, adds a newline after the text is displayed.

    .PARAMETER TextFunction
        A scriptblock that dynamically generates the text content. When specified, this takes
        precedence over the static Text parameter. Useful for displaying dynamic content that
        changes based on state or context.

    .PARAMETER TextFunctionArguments
        Arguments to pass to the TextFunction scriptblock. Should be a hashtable that will be
        splatted to the function.

    .OUTPUTS
        Returns a hashtable object with the following members:
        - Properties: Type, Text, BackgroundColor, ForegroundColor, AddNewLine, TextFunction, TextFunctionArguments
        - Methods: Draw(), GetText(), GetTextHeight(), GetTextWidth(), IsDynamicObject()

    .EXAMPLE
        $textObj = New-CLIDialogText -Text "Hello World" -ForegroundColor Green
        $textObj.Draw()

        Creates a simple green text object and displays it.

    .EXAMPLE
        $textObj = New-CLIDialogText -Text "Line 1`nLine 2`nLine 3" -AddNewLine
        $height = $textObj.GetTextHeight()

        Creates a multi-line text object and gets its height (returns 3).

    .EXAMPLE
        $dynText = New-CLIDialogText -TextFunction { Get-Date -Format "HH:mm:ss" }
        $dynText.Draw()

        Creates a dynamic text object that displays the current time when drawn.

    .EXAMPLE
        $textWithArgs = New-CLIDialogText -TextFunction {
            param($Name, $Value)
            "$Name = $Value"
        } -TextFunctionArguments @{ Name = "Server"; Value = "localhost" }

        Creates a dynamic text object with custom arguments.

    .NOTES
        Author: Loïc Ade
        Version: 1.1.0

        This function is part of the CLI Dialog framework and is typically used with New-CLIDialog.
        The returned object includes ANSI escape sequence filtering in GetTextWidth() for accurate
        width calculation when using colored or styled text.

        METHODS:
        - Draw(): Renders the text to the console with the specified colors
        - GetText(): Returns the text content (either static or from TextFunction)
        - GetTextHeight(): Returns the number of lines in the text
        - GetTextWidth(): Returns the width of the longest line (excluding ANSI codes)
        - IsDynamicObject(): Returns $false (indicates this is not a dynamic object)

        CHANGELOG:

        Version 1.1.0 - 2026-04-03 - Loïc Ade
            - Added theme support via Get-CLIDialogTheme for default colors

        Version 1.0.0 - 2025-10-20 - Loïc Ade
            - Initial release
            - Support for static and dynamic text
            - Multi-line text support
            - Custom color support
            - ANSI escape sequence handling
    #>
    Param(
        [Parameter(Position = 0)]
        [AllowEmptyString()]
        [string]$Text,
        [System.ConsoleColor]$BackgroundColor = (Get-CLIDialogTheme "BackgroundColor"),
        [System.ConsoleColor]$ForegroundColor = (Get-CLIDialogTheme "ForegroundColor"),
        [switch]$AddNewLine,
        [scriptblock]$TextFunction,
        [object]$TextFunctionArguments,
        [ValidateSet("None", "Truncate", "WordWrap")]
        [string]$OverflowMode = "Truncate"
    )
    $hResult = @{
        Type = "text"
        Text = $Text
        BackgroundColor = $BackgroundColor
        ForegroundColor = $ForegroundColor
        AddNewLine = $AddNewLine
        TextFunction = $TextFunction
        TextFunctionArguments = $TextFunctionArguments
        OverflowMode = $OverflowMode
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "Draw" -Value {
        $sText = $this.GetText()
        if ($null -eq $sText -or $sText -eq "") {
            if ($this.AddNewLine) { Write-Host "" } else { Write-Host "" -NoNewline }
            return
        }

        $iWindowWidth = $host.ui.RawUI.WindowSize.Width
        $aLines = $sText.Split("`n")
        $aOutputLines = @()

        foreach ($sLine in $aLines) {
            if ($this.OverflowMode -ne 'None' -and $sLine.Length -gt $iWindowWidth) {
                if ($this.OverflowMode -eq 'Truncate') {
                    $aOutputLines += $sLine.Substring(0, $iWindowWidth - 1) + [char]0x2026
                } else {
                    # WordWrap : couper aux espaces
                    $sRemaining = $sLine
                    while ($sRemaining.Length -gt $iWindowWidth) {
                        $iCut = $sRemaining.LastIndexOf(' ', $iWindowWidth - 1)
                        if ($iCut -le 0) { $iCut = $iWindowWidth - 1 }
                        $aOutputLines += $sRemaining.Substring(0, $iCut)
                        $sRemaining = $sRemaining.Substring($iCut).TrimStart()
                    }
                    if ($sRemaining.Length -gt 0) { $aOutputLines += $sRemaining }
                }
            } else {
                $aOutputLines += $sLine
            }
        }

        if ($aOutputLines.Count -gt 1 -or $this.AddNewLine) {
            foreach ($sOutLine in $aOutputLines) {
                Write-Host $sOutLine -ForegroundColor $this.ForegroundColor -BackgroundColor $this.BackgroundColor
            }
        } else {
            Write-Host $aOutputLines[0] -NoNewline -ForegroundColor $this.ForegroundColor -BackgroundColor $this.BackgroundColor
        }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "GetText" -Value {
        if ($this.TextFunction) {
            if ($null -ne $this.TextFunctionArguments) {
                $hArgs = $this.TextFunctionArguments
                $sResult = . $this.TextFunction @hArgs
            } else {
                $sResult = . $this.TextFunction 
            }
        } else {
            $sResult = $this.Text
        }
        return $sResult
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "GetTextHeight" -Value {
        $sText = $this.GetText()
        if ($null -eq $sText -or $sText -eq '') { return 1 }
        $aLines = $sText.Split("`n")
        if ($this.OverflowMode -eq 'WordWrap') {
            $iWindowWidth = $host.ui.RawUI.WindowSize.Width
            $iTotal = 0
            foreach ($sLine in $aLines) {
                if ($sLine.Length -gt $iWindowWidth -and $iWindowWidth -gt 0) {
                    $iTotal += [Math]::Ceiling($sLine.Length / $iWindowWidth)
                } else {
                    $iTotal++
                }
            }
            return $iTotal
        }
        return $aLines.Count
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "GetTextWidth" -Value {
        $iResult = 0
        $aText = $this.GetText().Split("`n")
        foreach ($sLine in $aText) {
            $sFilteredLine = $sLine -Replace "$([char]27)\[[^m]+m", ""
            if ($sFilteredLine.Length -gt $iResult) {
                $iResult = $sFilteredLine.Length
            }
        }
        return $iResult
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "IsDynamicObject" -Value {
        return $false
    }

    return $hResult
}
