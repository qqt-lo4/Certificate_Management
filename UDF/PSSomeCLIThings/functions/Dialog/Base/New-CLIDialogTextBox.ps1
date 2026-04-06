function New-CLIDialogTextBox {
    <#
    .SYNOPSIS
        Creates an editable text input field for CLI dialog interfaces.

    .DESCRIPTION
        This function creates an interactive text box control for user input in CLI dialogs.
        It provides a full-featured text editing experience with cursor positioning, keyboard
        navigation (arrows, Home, End, Backspace, Delete), validation (regex or scriptblock),
        password masking, secure string support, custom value conversion, and visual feedback
        for invalid input. The control displays a header label and an editable text field.

    .PARAMETER Header
        The label text displayed before the input field. This parameter is mandatory and can
        be used at position 0. Example: "Username", "Password", "Email Address".

    .PARAMETER HeaderAlign
        The alignment of the header label. Valid values are "Left" or "Right". Default is "Left".
        Right alignment is useful for creating form-like layouts with aligned colons.

    .PARAMETER HeaderSeparator
        The separator text between the header and input field. Default is " : ".
        Example: " = ", " -> ", " >> ".

    .PARAMETER TextForegroundColor
        The foreground color of the input text when not focused. Default is the current
        console foreground color.

    .PARAMETER TextBackgroundColor
        The background color of the input text when not focused. Default is the current
        console background color.

    .PARAMETER HeaderForegroundColor
        The foreground color of the header label when not focused. Default is Green.

    .PARAMETER HeaderBackgroundColor
        The background color of the header label when not focused. Default is the current
        console background color.

    .PARAMETER FocusedTextForegroundColor
        The foreground color of the input text when focused. Default is the current console
        foreground color.

    .PARAMETER FocusedTextBackgroundColor
        The background color of the input text when focused. Default is the current console
        background color.

    .PARAMETER FocusedHeaderForegroundColor
        The foreground color of the header label when focused. Default is Blue.

    .PARAMETER FocusedHeaderBackgroundColor
        The background color of the header label when focused. Default is the current console
        background color.

    .PARAMETER SeparatorLocation
        The column position where the separator should be located. Used for aligning multiple
        text boxes in a form layout. If not specified, uses the header length.

    .PARAMETER Text
        The initial text value. Can be a string, int, or SecureString. Default is empty string.
        - String/Int: Displayed as plain text (or masked if PasswordChar is set)
        - SecureString: Automatically converted to plain text internally and masked with "*"

    .PARAMETER Prefix
        The prefix string displayed before the header when not focused. Used for indentation
        or visual hierarchy.

    .PARAMETER FocusedPrefix
        The prefix string displayed before the header when focused. Typically used to indicate
        focus (e.g., "> " to show current field).

    .PARAMETER Regex
        A regular expression pattern for validation. The input text must match this pattern
        to be considered valid. Invalid input displays the header in ValidationErrorColor.

    .PARAMETER ValidationScript
        A scriptblock for custom validation. Receives the text as parameter and must return
        $true for valid or $false for invalid. Takes precedence over Regex if both are specified.

    .PARAMETER ValidationErrorColor
        The color used for the header when validation fails. Default is Red.

    .PARAMETER ValidationErrorReason
        A custom error message to display when validation fails. Used for user feedback.

    .PARAMETER FieldNameInErrorReason
        The field name to use in error messages. Useful for identifying which field failed
        validation in forms with multiple text boxes.

    .PARAMETER SelectionForegroundColor
        The foreground color of selected text. Default is the current console background color.

    .PARAMETER SelectionBackgroundColor
        The background color of selected text. Default is DarkCyan.

    .PARAMETER PasswordChar
        The character to use for masking input (e.g., '*' or '•'). When set, all characters
        are displayed as this character, but the actual text is preserved internally.

    .PARAMETER Name
        A unique identifier for the text box. If not specified, generates a name based on
        the header (e.g., "textboxUsername"). Used for identification and retrieval.

    .PARAMETER ValueConvertFunction
        A scriptblock to convert the text value when GetValue() is called. Useful for parsing
        numbers, dates, or custom types from string input.

    .OUTPUTS
        Returns a hashtable object with the following members:
        - Properties: Type, Header, HeaderAlign, HeaderSeparator, Colors, SeparatorLocation, Text,
                     OriginalText, Prefix, FocusedPrefix, CursorPosition, Regex, ValidationScript,
                     ValidationErrorColor, FieldNameInErrorReason, ValidationErrorReason, LastValidation,
                     PasswordChar, Name, ValueConvertFunction
        - Methods: IsValidText(), Draw(), DrawFocused(), PressLeft(), PressRight(), PressBackspace(),
                   PressDelete(), PressHome(), PressEnd(), PressUp(), PressDown(), PressKey(),
                   SetCursorPosition(), GetTextHeight(), GetTextWidth(), Reset(), GetValue(),
                   IsDynamicObject()

    .EXAMPLE
        $nameBox = New-CLIDialogTextBox -Header "Name" -Text "John Doe"
        $nameBox.DrawFocused()

        Creates a text box for name input with initial value "John Doe".

    .EXAMPLE
        $emailBox = New-CLIDialogTextBox -Header "Email" -Regex "^[\w-\.]+@([\w-]+\.)+[\w-]{2,4}$"
        # Invalid email will show header in red

        Creates a text box with email validation using regex pattern.

    .EXAMPLE
        $passwordBox = New-CLIDialogTextBox -Header "Password" -PasswordChar '*'
        $securePassword = $passwordBox.GetValue()  # Returns SecureString

        Creates a password text box with asterisk masking.

    .EXAMPLE
        $ageBox = New-CLIDialogTextBox -Header "Age" -ValidationScript {
            param($text)
            [int]$age = 0
            return [int]::TryParse($text, [ref]$age) -and $age -ge 18 -and $age -le 120
        } -ValueConvertFunction { param($text) [int]$text }
        $age = $ageBox.GetValue()  # Returns integer

        Creates a text box for age with custom validation and type conversion.

    .EXAMPLE
        $formFields = @(
            New-CLIDialogTextBox -Header "Username" -SeparatorLocation 15 -Prefix "  " -FocusedPrefix "> "
            New-CLIDialogTextBox -Header "Email" -SeparatorLocation 15 -Prefix "  " -FocusedPrefix "> "
            New-CLIDialogTextBox -Header "Phone" -SeparatorLocation 15 -Prefix "  " -FocusedPrefix "> "
        )

        Creates aligned form fields with consistent separator location and focus indicators.

    .EXAMPLE
        $secureBox = New-CLIDialogTextBox -Header "API Key" -Text (ConvertTo-SecureString "secret" -AsPlainText -Force)
        # Automatically displays as "******"

        Creates a text box initialized with a SecureString value.

    .NOTES
        Module: CLIDialog
        Author: Loïc Ade
        Created: 2025-10-20
        Version: 2.0.0
        Dependencies: None

        This function is part of the CLI Dialog framework. Text boxes are the primary control
        for text input in forms and interactive dialogs.

        KEYBOARD NAVIGATION:
        - Left/Right Arrow: Move cursor within text
        - Shift+Left/Right Arrow: Extend selection
        - Home: Jump to beginning of text
        - End: Jump to end of text
        - Shift+Home/End: Extend selection to start/end
        - Ctrl+A: Select all text
        - Ctrl+C: Copy selected text to clipboard (disabled for password fields)
        - Ctrl+X: Cut selected text to clipboard (disabled for password fields)
        - Ctrl+V: Paste from clipboard (replaces selection if any)
        - Ctrl+Up Arrow: Previous value from history
        - Ctrl+Down Arrow: Next value from history
        - Backspace: Delete character before cursor (or delete selection)
        - Delete: Delete character at cursor (or delete selection)
        - Up/Down Arrow: Navigate between text boxes (returns control to dialog)
        - Regular characters: Insert at cursor position (replaces selection if any)

        VALIDATION:
        - Validation is performed on-demand via IsValidText() method
        - Results are cached until text changes
        - Invalid text displays header in ValidationErrorColor
        - Both Regex and ValidationScript are supported (ValidationScript takes precedence)

        HISTORY:
        - Ctrl+Up/Down navigates through previously validated values
        - History is stored globally in $Global:CLIDialogHistory, keyed by TextBox Name
        - Values are saved automatically when dialog is validated (Invoke-CLIDialog)
        - Password fields are excluded from history
        - Duplicate consecutive values are not saved
        - Ctrl+Down from the last entry returns to the text being typed

        PASSWORD HANDLING:
        - PasswordChar masks all characters during display
        - Internal Text property stores actual unmasked text
        - GetValue() returns SecureString when PasswordChar is set
        - SecureString input is automatically detected and masked

        CURSOR DISPLAY:
        - Focused text box shows cursor as inverted colors at current position
        - Cursor at end of text shows as white space block
        - Cursor within text shows as inverted character

        METHODS:
        - IsValidText(): Returns true if text passes validation (cached)
        - Draw(): Renders text box in normal state
        - DrawFocused(): Renders with focus, shows cursor at CursorPosition
        - PressLeft/Right/Home/End(): Cursor movement methods
        - PressBackspace/Delete(): Text editing methods
        - PressUp/Down(): Returns navigation object to move between fields
        - PressKey([ConsoleKeyInfo]): Main keyboard handler, dispatches to specific methods
        - SetCursorPosition([int]): Programmatically set cursor position (with bounds checking)
        - GetTextHeight(): Returns number of lines (always 1 for textbox)
        - GetTextWidth(): Returns total width (prefix + header + separator + text)
        - Reset(): Restores to OriginalText value
        - GetValue(): Returns value (SecureString for passwords, converted value if function set, or plain text)
        - IsDynamicObject(): Returns $true (textbox is interactive)

        CHANGELOG:

        Version 2.0.0 - 2026-04-05 - Loïc Ade
            Overflow:
            - Added sliding window for text longer than available width
            - Left/right arrow indicators (◄/►) for overflow direction
            - Cursor-centered viewport with smooth scrolling
            - Overflow indicator in unfocused Draw() method
            Selection and clipboard:
            - Added text selection support (Shift+Left/Right/Home/End, Ctrl+A)
            - Added clipboard support (Ctrl+C copy, Ctrl+V paste, Ctrl+X cut)
            - Ctrl+C/X disabled for password fields (security)
            - Selection-aware rendering in DrawFocused (fits and overflow modes)
            - Selection-aware editing: typing, Backspace, Delete replace selection
            Input history:
            - Added input history support (Ctrl+Up/Down)
            - History stored globally in $Global:CLIDialogHistory, keyed by Name
            - Values saved on dialog validation, password fields excluded
            Multi-line mode:
            - Added multi-line text input mode (-MultiLine switch)
            - Dynamic height: grows with content (MinVisibleLines to MaxVisibleLines)
            - Enter key inserts new lines, Up/Down navigate between lines
            - Navigation to/from other controls at first/last line boundaries
            - Home/End navigate within current line, Ctrl+Home/End for entire text
            - Ctrl+V preserves newlines in multi-line mode
            - Vertical scrolling with viewport when lines exceed MaxVisibleLines
            New parameters: MultiLine, MinVisibleLines, MaxVisibleLines,
              MultiLineOverflowMode, SelectionForegroundColor,
              SelectionBackgroundColor, SelectionCursorBackgroundColor
            New properties: SelectionAnchor, HistoryIndex, HistoryCurrentText,
              ViewportTopLine
            New methods: HasSelection, GetSelectionStart, GetSelectionEnd,
              GetSelectedText, ClearSelection, DeleteSelection, PressSelectAll,
              PressCopy, PressPaste, PressCut, GetHistory, SaveToHistory,
              PressHistoryUp, PressHistoryDown, GetLines, GetCursorLineColumn,
              GetFlatPosition, GetCurrentVisibleLineCount, EnsureCursorVisible,
              SetCursorPositionAtLine, DrawLine, DrawFocusedLineContent

        Version 1.0.0 - 2025-10-20 - Loïc Ade
            - Initial release
            - Full keyboard navigation and text editing
            - Regex and scriptblock validation with visual feedback
            - Password masking with character replacement
            - SecureString input and output support
            - Custom value conversion via scriptblock
            - Aligned form layouts with SeparatorLocation
            - Focus state with color customization
            - Cursor position display with inverted colors
            - Validation result caching for performance
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Header,
        [ValidateSet("Left", "Right")]
        [string]$HeaderAlign = "Left",
        [string]$HeaderSeparator = " : ",
        [System.ConsoleColor]$TextForegroundColor = (Get-CLIDialogTheme "ForegroundColor"),
        [System.ConsoleColor]$TextBackgroundColor = (Get-CLIDialogTheme "BackgroundColor"),
        [System.ConsoleColor]$HeaderForegroundColor = (Get-CLIDialogTheme "HeaderForegroundColor"),
        [System.ConsoleColor]$HeaderBackgroundColor = (Get-CLIDialogTheme "HeaderBackgroundColor"),
        [System.ConsoleColor]$FocusedTextForegroundColor = (Get-CLIDialogTheme "ForegroundColor"),
        [System.ConsoleColor]$FocusedTextBackgroundColor = (Get-CLIDialogTheme "BackgroundColor"),
        [System.ConsoleColor]$FocusedHeaderForegroundColor = (Get-CLIDialogTheme "FocusedHeaderForegroundColor"),
        [System.ConsoleColor]$FocusedHeaderBackgroundColor = (Get-CLIDialogTheme "FocusedHeaderBackgroundColor"),
        [int]$SeparatorLocation,
        [object]$Text = "",
        [string]$Prefix,
        [string]$FocusedPrefix,
        [string]$Regex,
        [object]$ValidationScript,
        [System.ConsoleColor]$SelectionForegroundColor = (Get-CLIDialogTheme "SelectionForegroundColor"),
        [System.ConsoleColor]$SelectionBackgroundColor = (Get-CLIDialogTheme "SelectionBackgroundColor"),
        [System.ConsoleColor]$SelectionCursorBackgroundColor = (Get-CLIDialogTheme "SelectionCursorBackgroundColor"),
        [System.ConsoleColor]$OverflowIndicatorColor = (Get-CLIDialogTheme "OverflowIndicatorColor"),
        [string]$OverflowIndicatorLeft = (Get-CLIDialogTheme "OverflowIndicatorLeft"),
        [string]$OverflowIndicatorRight = (Get-CLIDialogTheme "OverflowIndicatorRight"),
        [System.ConsoleColor]$ValidationErrorColor = (Get-CLIDialogTheme "ValidationErrorColor"),
        [string]$ValidationErrorReason,
        [string]$FieldNameInErrorReason,
        [char]$PasswordChar,
        [string]$Name,
        [object]$ValueConvertFunction,
        [switch]$MultiLine,
        [int]$MinVisibleLines = 1,
        [int]$MaxVisibleLines = 5,
        [ValidateSet("Truncate", "WordWrap")]
        [string]$MultiLineOverflowMode = "Truncate"
    )
    $sText, $sPasswordChar = if (($Text -is [string]) -or ($Text -is [int])) {
        $sTextResult = $Text.ToString()
        $sPasswordCharResult = if ($PasswordChar) { $PasswordChar } else { $null }
        $sTextResult, $sPasswordCharResult
    } elseif ($Text -is [securestring]) {
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Text)
        $UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR) | Out-Null
        $sPasswordCharResult = if ($PasswordChar) { $PasswordChar } else { "*" }
        $UnsecurePassword, $sPasswordCharResult
    } else {
        throw [System.ArgumentException] "Unsupported `$Text type"
    }
    $hResult = @{
        Type = "textbox"
        Header = $Header
        HeaderAlign = $HeaderAlign
        HeaderSeparator = $HeaderSeparator
        TextBackgroundColor = $TextBackgroundColor
        TextForegroundColor = $TextForegroundColor
        HeaderBackgroundColor = $HeaderBackgroundColor
        HeaderForegroundColor = $HeaderForegroundColor
        FocusedTextBackgroundColor = $FocusedTextBackgroundColor
        FocusedTextForegroundColor = $FocusedTextForegroundColor
        FocusedHeaderBackgroundColor = $FocusedHeaderBackgroundColor
        FocusedHeaderForegroundColor = $FocusedHeaderForegroundColor
        SeparatorLocation = $SeparatorLocation
        Text = $sText
        OriginalText = $sText
        Prefix = $Prefix
        FocusedPrefix = $FocusedPrefix
        CursorPosition = if ($sText) { $sText.Length } else { 0 }
        SelectionAnchor = $null
        SelectionForegroundColor = $SelectionForegroundColor
        SelectionBackgroundColor = $SelectionBackgroundColor
        SelectionCursorBackgroundColor = $SelectionCursorBackgroundColor
        OverflowIndicatorColor = $OverflowIndicatorColor
        OverflowIndicatorLeft = $OverflowIndicatorLeft
        OverflowIndicatorRight = $OverflowIndicatorRight
        Regex = $Regex
        ValidationScript = $ValidationScript
        ValidationErrorColor = $ValidationErrorColor
        FieldNameInErrorReason = $FieldNameInErrorReason
        ValidationErrorReason = $ValidationErrorReason
        LastValidation = $true
        PasswordChar = $sPasswordChar
        Name = if ($Name) { $Name } else { "textbox" + $Header.Replace("$([char]27)[4m", "").Replace("$([char]27)[24m", "").Replace(" ", "") }
        ValueConvertFunction = $ValueConvertFunction
        HistoryIndex = -1
        HistoryCurrentText = $null
        MultiLine = [bool]$MultiLine
        MinVisibleLines = if ($MultiLine) { [Math]::Max($MinVisibleLines, 2) } else { 1 }
        MaxVisibleLines = if ($MultiLine) { $MaxVisibleLines } else { 1 }
        MultiLineOverflowMode = $MultiLineOverflowMode
        ViewportTopLine = 0
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "GetLines" -Value {
        return ,$this.Text.Split("`n")
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "GetCursorLineColumn" -Value {
        $aLines = $this.GetLines()
        $iPos = 0
        for ($i = 0; $i -lt $aLines.Count; $i++) {
            if ($this.CursorPosition -le ($iPos + $aLines[$i].Length)) {
                return @{ Line = $i; Column = $this.CursorPosition - $iPos }
            }
            $iPos += $aLines[$i].Length + 1
        }
        $iLast = $aLines.Count - 1
        return @{ Line = $iLast; Column = $aLines[$iLast].Length }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "GetFlatPosition" -Value {
        Param([int]$Line, [int]$Column)
        $aLines = $this.GetLines()
        $iPos = 0
        for ($i = 0; $i -lt $Line; $i++) {
            $iPos += $aLines[$i].Length + 1
        }
        return $iPos + [Math]::Min($Column, $aLines[$Line].Length)
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "GetCurrentVisibleLineCount" -Value {
        if (-not $this.MultiLine) { return 1 }
        $iLineCount = $this.GetLines().Count
        return [Math]::Max($this.MinVisibleLines, [Math]::Min($iLineCount, $this.MaxVisibleLines))
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "EnsureCursorVisible" -Value {
        if (-not $this.MultiLine) { return }
        $iCursorLine = $this.GetCursorLineColumn().Line
        $iVisibleLines = $this.GetCurrentVisibleLineCount()
        if ($iCursorLine -lt $this.ViewportTopLine) {
            $this.ViewportTopLine = $iCursorLine
        } elseif ($iCursorLine -ge ($this.ViewportTopLine + $iVisibleLines)) {
            $this.ViewportTopLine = $iCursorLine - $iVisibleLines + 1
        }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "IsValidText" -Value {
        if ($this.Regex -or $this.ValidationScript) {
            if ($this.LastTestedText -eq $this.Text) {
                return $this.LastValidation
            } else {
                $this.LastValidation, $this.LastValidationDetails = if ($this.Regex) {
                    $bValidationResult = Select-String -InputObject $this.Text -Pattern $this.Regex -AllMatches
                    $bValidationResult -ne $null
                    $bValidationResult
                } else {
                    $bValidationResult = Invoke-Command -ScriptBlock $this.ValidationScript -ArgumentList $this.Text
                    if ($bValidationResult) {
                        $true, $bValidationResult
                    } else {
                        $false, $false
                    }
                }
                $this.LastTestedText = $this.Text
                return $this.LastValidation
            }
        } else {
            return $true
        }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "HasSelection" -Value {
        return ($null -ne $this.SelectionAnchor -and $this.SelectionAnchor -ne $this.CursorPosition)
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "GetSelectionStart" -Value {
        if ($null -eq $this.SelectionAnchor) { return $this.CursorPosition }
        if ($this.SelectionAnchor -lt $this.CursorPosition) {
            return $this.SelectionAnchor
        } else {
            return $this.CursorPosition
        }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "GetSelectionEnd" -Value {
        if ($null -eq $this.SelectionAnchor) { return $this.CursorPosition }
        if ($this.SelectionAnchor -gt $this.CursorPosition) {
            return $this.SelectionAnchor
        } else {
            return $this.CursorPosition
        }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "GetSelectedText" -Value {
        if (-not $this.HasSelection()) { return "" }
        $iStart = $this.GetSelectionStart()
        $iEnd = $this.GetSelectionEnd()
        return $this.Text.Substring($iStart, $iEnd - $iStart)
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "ClearSelection" -Value {
        $this.SelectionAnchor = $null
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "DeleteSelection" -Value {
        if (-not $this.HasSelection()) { return $false }
        $iStart = $this.GetSelectionStart()
        $iEnd = $this.GetSelectionEnd()
        $sPrefix = if ($iStart -gt 0) { $this.Text.Substring(0, $iStart) } else { "" }
        $sSuffix = if ($iEnd -lt $this.Text.Length) { $this.Text.Substring($iEnd) } else { "" }
        $this.Text = $sPrefix + $sSuffix
        $this.CursorPosition = $iStart
        $this.SelectionAnchor = $null
        return $true
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "DrawLine" -Value {
        Param([string]$LineText, [int]$AvailableWidth, [string]$HeaderText, [System.ConsoleColor]$HeaderFG, [System.ConsoleColor]$HeaderBG)
        if ($HeaderText) {
            Write-Host $HeaderText -ForegroundColor $HeaderFG -BackgroundColor $HeaderBG -NoNewline
        }
        $sPrintedLine = if ($this.PasswordChar) { $this.PasswordChar.ToString() * $LineText.Length } else { $LineText }
        if ($sPrintedLine.Length -gt $AvailableWidth -and $AvailableWidth -gt 2) {
            $sVisible = $sPrintedLine.Substring(0, $AvailableWidth - 1)
            Write-Host $sVisible -ForegroundColor $this.TextForegroundColor -BackgroundColor $this.TextBackgroundColor -NoNewline
            Write-Host $this.OverflowIndicatorRight -ForegroundColor $this.OverflowIndicatorColor -BackgroundColor $this.TextBackgroundColor
        } else {
            Write-Host $sPrintedLine -ForegroundColor $this.TextForegroundColor -BackgroundColor $this.TextBackgroundColor -NoNewline
            $iRemaining = [Math]::Max(0, $AvailableWidth - $sPrintedLine.Length)
            Write-Host (" " * $iRemaining)
        }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "Draw" -Value {
        $iAlign = if ($this.HeaderAlign -eq "Left") { -1 } else { 1 }
        $sHeader = ("" + $this.Prefix + ("{0,$($this.SeparatorLocation * $iAlign)}" -f $this.Header) + $this.HeaderSeparator)
        $oHeaderColor = if ($this.IsValidText()) {
            $this.HeaderForegroundColor
        } else {
            $this.ValidationErrorColor
        }
        $iAvailableWidth = $host.ui.RawUI.WindowSize.Width - $sHeader.Length
        if ($this.MultiLine) {
            $aLines = $this.GetLines()
            $sLinePadding = " " * $sHeader.Length
            $iVisibleLines = $this.GetCurrentVisibleLineCount()
            for ($i = 0; $i -lt $iVisibleLines; $i++) {
                $iLineIndex = $this.ViewportTopLine + $i
                $sLineText = if ($iLineIndex -lt $aLines.Count) { [string]$aLines[$iLineIndex] } else { "" }
                $sLineHeader = if ($i -eq 0) { $sHeader } else { $sLinePadding }
                $oLineFG = if ($i -eq 0) { $oHeaderColor } else { $this.HeaderBackgroundColor }
                $this.DrawLine($sLineText, $iAvailableWidth, $sLineHeader, $oLineFG, $this.HeaderBackgroundColor)
            }
        } else {
            $sPrintedText = if ($this.PasswordChar) { $this.PasswordChar.ToString() * $this.Text.Length } else { $this.Text }
            $this.DrawLine($sPrintedText, $iAvailableWidth, $sHeader, $oHeaderColor, $this.HeaderBackgroundColor)
        }
    }

    # Renders a single line of text with cursor and selection support
    $hResult | Add-Member -MemberType ScriptMethod -Name "DrawFocusedLineContent" -Value {
        Param([string]$sFullText, [int]$iAvailableWidth, [int]$iCursorPos, [bool]$bShowCursor, [int]$iSelStart, [int]$iSelEnd, [bool]$bHasSelection)
        $bCursorAtEnd = $bShowCursor -and ($iCursorPos -eq $sFullText.Length)
        $iCursorExtra = if ($bCursorAtEnd) { 1 } else { 0 }

        if (($sFullText.Length + $iCursorExtra) -le $iAvailableWidth) {
            # === Text fits entirely ===
            if ($bHasSelection -and ($iSelEnd -gt $iSelStart)) {
                # Clamp selection to this line
                $iLS = [Math]::Max(0, $iSelStart)
                $iLE = [Math]::Min($sFullText.Length, $iSelEnd)
                if ($iLE -gt $iLS) {
                    $sBeforeSel = if ($iLS -gt 0) { $sFullText.Substring(0, $iLS) } else { "" }
                    $sSelected = $sFullText.Substring($iLS, $iLE - $iLS)
                    $sAfterSel = if ($iLE -lt $sFullText.Length) { $sFullText.Substring($iLE) } else { "" }

                    if ($sBeforeSel.Length -gt 0) {
                        Write-Host $sBeforeSel -NoNewline -ForegroundColor $this.FocusedTextForegroundColor -BackgroundColor $this.FocusedTextBackgroundColor
                    }
                    if ($bShowCursor -and $iCursorPos -eq $iLS) {
                        Write-Host $sSelected[0] -NoNewline -ForegroundColor $this.SelectionForegroundColor -BackgroundColor $this.SelectionCursorBackgroundColor
                        if ($sSelected.Length -gt 1) {
                            Write-Host ($sSelected.Substring(1)) -NoNewline -ForegroundColor $this.SelectionForegroundColor -BackgroundColor $this.SelectionBackgroundColor
                        }
                    } elseif ($bShowCursor -and $iCursorPos -eq $iLE) {
                        if ($sSelected.Length -gt 1) {
                            Write-Host ($sSelected.Substring(0, $sSelected.Length - 1)) -NoNewline -ForegroundColor $this.SelectionForegroundColor -BackgroundColor $this.SelectionBackgroundColor
                        }
                        Write-Host $sSelected[$sSelected.Length - 1] -NoNewline -ForegroundColor $this.SelectionForegroundColor -BackgroundColor $this.SelectionCursorBackgroundColor
                    } else {
                        Write-Host $sSelected -NoNewline -ForegroundColor $this.SelectionForegroundColor -BackgroundColor $this.SelectionBackgroundColor
                    }
                    if ($bCursorAtEnd) {
                        Write-Host " " -ForegroundColor Black -BackgroundColor White -NoNewline
                        $sAfterSel = ""
                    }
                    if ($sAfterSel.Length -gt 0) {
                        Write-Host $sAfterSel -NoNewline -ForegroundColor $this.FocusedTextForegroundColor -BackgroundColor $this.FocusedTextBackgroundColor
                    }
                } else {
                    # Selection doesn't intersect this line
                    $this.DrawFocusedLineContent($sFullText, $iAvailableWidth, $iCursorPos, $bShowCursor, 0, 0, $false)
                    return
                }
            } else {
                # No selection
                if ($sFullText.Length -gt 0) {
                    if ($bShowCursor -and ($iCursorPos -ge 1)) {
                        Write-Host ($sFullText.Substring(0, $iCursorPos)) -NoNewline -ForegroundColor $this.FocusedTextForegroundColor -BackgroundColor $this.FocusedTextBackgroundColor
                    } elseif (-not $bShowCursor) {
                        Write-Host $sFullText -NoNewline -ForegroundColor $this.FocusedTextForegroundColor -BackgroundColor $this.FocusedTextBackgroundColor
                    }
                    if ($bShowCursor -and -not $bCursorAtEnd) {
                        Write-Host $sFullText[$iCursorPos] -NoNewline -ForegroundColor $this.FocusedTextBackgroundColor -BackgroundColor $this.FocusedTextForegroundColor
                    }
                    if ($bShowCursor -and ($iCursorPos + 1 -lt $sFullText.Length)) {
                        Write-Host ($sFullText.Substring($iCursorPos + 1)) -NoNewline -ForegroundColor $this.FocusedTextForegroundColor -BackgroundColor $this.FocusedTextBackgroundColor
                    }
                }
                if ($bCursorAtEnd) {
                    Write-Host " " -ForegroundColor Black -BackgroundColor White -NoNewline
                }
            }
            if ($bCursorAtEnd) {
                $iRemaining = [Math]::Max(0, $iAvailableWidth - $sFullText.Length - 1)
            } else {
                $iRemaining = [Math]::Max(0, $iAvailableWidth - $sFullText.Length)
            }
            Write-Host (" " * $iRemaining)
        } else {
            # === Text overflows: sliding window ===
            $iLocalCursor = if ($bShowCursor) { $iCursorPos } else { 0 }
            $iViewStart = $iLocalCursor - [Math]::Floor($iAvailableWidth / 2)
            if ($iViewStart -lt 0) { $iViewStart = 0 }
            $iViewEnd = $iViewStart + $iAvailableWidth - $iCursorExtra
            if ($iViewEnd -gt $sFullText.Length) {
                $iViewEnd = $sFullText.Length
                $iViewStart = [Math]::Max(0, $iViewEnd - $iAvailableWidth + $iCursorExtra)
            }
            $bShowLeftArrow = ($iViewStart -gt 0)
            $bShowRightArrow = ($iViewEnd -lt $sFullText.Length)
            if ($bShowLeftArrow) { $iViewStart++ }
            if ($bShowRightArrow) { $iViewEnd-- }
            $sVisibleText = $sFullText.Substring($iViewStart, $iViewEnd - $iViewStart)
            $iCursorInWindow = $iLocalCursor - $iViewStart

            if ($bShowLeftArrow) {
                Write-Host $this.OverflowIndicatorLeft -NoNewline -ForegroundColor $this.OverflowIndicatorColor -BackgroundColor $this.FocusedTextBackgroundColor
            }

            $iWinSelStart = [Math]::Max(0, $iSelStart - $iViewStart)
            $iWinSelEnd = [Math]::Min($sVisibleText.Length, $iSelEnd - $iViewStart)
            $bHasVisibleSel = $bHasSelection -and ($iWinSelEnd -gt $iWinSelStart)

            if ($bHasVisibleSel) {
                if ($iWinSelStart -gt 0) {
                    Write-Host ($sVisibleText.Substring(0, $iWinSelStart)) -NoNewline -ForegroundColor $this.FocusedTextForegroundColor -BackgroundColor $this.FocusedTextBackgroundColor
                }
                $sWinSel = $sVisibleText.Substring($iWinSelStart, $iWinSelEnd - $iWinSelStart)
                if ($bShowCursor -and $iCursorInWindow -eq $iWinSelStart) {
                    Write-Host $sWinSel[0] -NoNewline -ForegroundColor $this.SelectionForegroundColor -BackgroundColor $this.SelectionCursorBackgroundColor
                    if ($sWinSel.Length -gt 1) { Write-Host ($sWinSel.Substring(1)) -NoNewline -ForegroundColor $this.SelectionForegroundColor -BackgroundColor $this.SelectionBackgroundColor }
                } else {
                    if ($sWinSel.Length -gt 1) { Write-Host ($sWinSel.Substring(0, $sWinSel.Length - 1)) -NoNewline -ForegroundColor $this.SelectionForegroundColor -BackgroundColor $this.SelectionBackgroundColor }
                    if ($bShowCursor -and $iCursorInWindow -eq $iWinSelEnd) {
                        Write-Host $sWinSel[$sWinSel.Length - 1] -NoNewline -ForegroundColor $this.SelectionForegroundColor -BackgroundColor $this.SelectionCursorBackgroundColor
                    } else {
                        Write-Host $sWinSel[$sWinSel.Length - 1] -NoNewline -ForegroundColor $this.SelectionForegroundColor -BackgroundColor $this.SelectionBackgroundColor
                    }
                }
                if ($iWinSelEnd -lt $sVisibleText.Length) {
                    Write-Host ($sVisibleText.Substring($iWinSelEnd)) -NoNewline -ForegroundColor $this.FocusedTextForegroundColor -BackgroundColor $this.FocusedTextBackgroundColor
                }
            } else {
                if ($sVisibleText.Length -gt 0) {
                    if ($bShowCursor -and $iCursorInWindow -gt 0) { Write-Host ($sVisibleText.Substring(0, $iCursorInWindow)) -NoNewline -ForegroundColor $this.FocusedTextForegroundColor -BackgroundColor $this.FocusedTextBackgroundColor }
                    elseif (-not $bShowCursor) { Write-Host $sVisibleText -NoNewline -ForegroundColor $this.FocusedTextForegroundColor -BackgroundColor $this.FocusedTextBackgroundColor }
                    if ($bShowCursor -and $iCursorInWindow -ge 0 -and $iCursorInWindow -lt $sVisibleText.Length) {
                        Write-Host $sVisibleText[$iCursorInWindow] -NoNewline -ForegroundColor $this.FocusedTextBackgroundColor -BackgroundColor $this.FocusedTextForegroundColor
                    }
                    if ($bShowCursor -and $iCursorInWindow + 1 -lt $sVisibleText.Length) { Write-Host ($sVisibleText.Substring($iCursorInWindow + 1)) -NoNewline -ForegroundColor $this.FocusedTextForegroundColor -BackgroundColor $this.FocusedTextBackgroundColor }
                }
            }
            if ($bCursorAtEnd -and -not $bShowRightArrow) {
                Write-Host " " -ForegroundColor Black -BackgroundColor White -NoNewline
            }
            if ($bShowRightArrow) {
                Write-Host $this.OverflowIndicatorRight -NoNewline -ForegroundColor $this.OverflowIndicatorColor -BackgroundColor $this.FocusedTextBackgroundColor
            }
            Write-Host ""
        }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "DrawFocused" -Value {
        # Write Header
        $iAlign = if ($this.HeaderAlign -eq "Left") { -1 } else { 1 }
        $sPropertyToScreen = ("" + $this.FocusedPrefix + ("{0,$($this.SeparatorLocation * $iAlign)}" -f $this.Header) + $this.HeaderSeparator)
        $oHeaderColor = if ($this.IsValidText()) {
            $this.FocusedHeaderForegroundColor
        } else {
            $this.ValidationErrorColor
        }

        # Clamp cursor position
        if ($this.CursorPosition -lt 0) { $this.CursorPosition = 0 }
        elseif ($this.CursorPosition -gt $this.Text.Length) { $this.CursorPosition = $this.Text.Length }

        $iAvailableWidth = $host.ui.RawUI.WindowSize.Width - $sPropertyToScreen.Length
        $bHasSelection = $this.HasSelection()
        $iSelStart = $this.GetSelectionStart()
        $iSelEnd = $this.GetSelectionEnd()

        if ($this.MultiLine) {
            $aLines = $this.GetLines()
            $sLinePadding = " " * $sPropertyToScreen.Length
            $oCursor = $this.GetCursorLineColumn()
            $iVisibleLines = $this.GetCurrentVisibleLineCount()
            $iFlatPos = 0
            # Calculate flat position of ViewportTopLine
            for ($j = 0; $j -lt $this.ViewportTopLine; $j++) {
                $iFlatPos += $aLines[$j].Length + 1
            }
            for ($i = 0; $i -lt $iVisibleLines; $i++) {
                $iLineIndex = $this.ViewportTopLine + $i
                # Header or padding
                if ($i -eq 0) {
                    Write-Host $sPropertyToScreen -NoNewline -ForegroundColor $oHeaderColor -BackgroundColor $this.FocusedHeaderBackgroundColor
                } else {
                    Write-Host $sLinePadding -NoNewline
                }
                if ($iLineIndex -lt $aLines.Count) {
                    $sLine = [string]$aLines[$iLineIndex]
                    $bCursorOnThisLine = ($iLineIndex -eq $oCursor.Line)
                    $iLineCursorPos = if ($bCursorOnThisLine) { $oCursor.Column } else { 0 }
                    # Map selection to line-local coordinates
                    $iLineSelStart = [Math]::Max(0, $iSelStart - $iFlatPos)
                    $iLineSelEnd = [Math]::Min($sLine.Length, $iSelEnd - $iFlatPos)
                    $bLineSel = $bHasSelection -and ($iLineSelEnd -gt $iLineSelStart)
                    $this.DrawFocusedLineContent($sLine, $iAvailableWidth, $iLineCursorPos, $bCursorOnThisLine, $iLineSelStart, $iLineSelEnd, $bLineSel)
                } else {
                    # Empty padding line
                    Write-Host (" " * $iAvailableWidth)
                }
                if ($iLineIndex -lt $aLines.Count) {
                    $iFlatPos += $aLines[$iLineIndex].Length + 1
                }
            }
        } else {
            Write-Host $sPropertyToScreen -NoNewline -ForegroundColor $oHeaderColor -BackgroundColor $this.FocusedHeaderBackgroundColor
            $sFullText = if ($this.PasswordChar) { $this.PasswordChar.ToString() * $this.Text.Length } else { $this.Text }
            $this.DrawFocusedLineContent($sFullText, $iAvailableWidth, $this.CursorPosition, $true, $iSelStart, $iSelEnd, $bHasSelection)
        }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "PressLeft" -Value {
        Param([bool]$Shift = $false)
        if ($Shift) {
            if ($null -eq $this.SelectionAnchor) { $this.SelectionAnchor = $this.CursorPosition }
            if ($this.CursorPosition -gt 0) { $this.CursorPosition-- }
        } else {
            if ($this.HasSelection()) {
                $this.CursorPosition = $this.GetSelectionStart()
                $this.ClearSelection()
            } elseif ($this.CursorPosition -eq 0) {
                return [System.ConsoleKeyInfo]::LeftArrow
            } else {
                $this.CursorPosition--
                $this.ClearSelection()
            }
        }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "PressRight" -Value {
        Param([bool]$Shift = $false)
        if ($Shift) {
            if ($null -eq $this.SelectionAnchor) { $this.SelectionAnchor = $this.CursorPosition }
            if ($this.CursorPosition -lt $this.Text.Length) { $this.CursorPosition++ }
        } else {
            if ($this.HasSelection()) {
                $this.CursorPosition = $this.GetSelectionEnd()
                $this.ClearSelection()
            } elseif ($this.CursorPosition -eq $this.Text.Length) {
                return [System.ConsoleKeyInfo]::RightArrow
            } else {
                $this.CursorPosition++
                $this.ClearSelection()
            }
        }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "PressBackspace" -Value {
        if ($this.HasSelection()) {
            $this.DeleteSelection() | Out-Null
            if ($this.MultiLine) { $this.EnsureCursorVisible() }
            return
        }
        if ($this.CursorPosition -gt 0) {
            $sPrefix = if ($this.CursorPosition -le 1) {
                ""
            } else {
                $this.Text.Substring(0, $this.CursorPosition - 1)
            }
            $sSuffix = if ($this.CursorPosition -lt $this.Text.Length) {
                $this.Text.Substring($this.CursorPosition)
            } else {
                ""
            }
            $this.Text = $sPrefix + $sSuffix
            $this.CursorPosition--
            if ($this.MultiLine) { $this.EnsureCursorVisible() }
        }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "PressDelete" -Value {
        if ($this.HasSelection()) {
            $this.DeleteSelection() | Out-Null
            return
        }
        if ($this.CursorPosition -lt $this.Text.Length) {
            $sPrefix = if ($this.CursorPosition -gt 0) {
                $this.Text.Substring(0, $this.CursorPosition)
            } else {
                ""
            }
            $sSuffix = if ($this.CursorPosition + 1 -lt $this.Text.Length) {
                $this.Text.Substring($this.CursorPosition + 1)
            } else {
                ""
            }
            $this.Text = $sPrefix + $sSuffix
        }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "PressHome" -Value {
        Param([bool]$Shift = $false, [bool]$Ctrl = $false)
        if ($Shift) {
            if ($null -eq $this.SelectionAnchor) { $this.SelectionAnchor = $this.CursorPosition }
        } else {
            $this.ClearSelection()
        }
        if ($this.MultiLine -and -not $Ctrl) {
            $oCursor = $this.GetCursorLineColumn()
            $this.CursorPosition = $this.GetFlatPosition($oCursor.Line, 0)
        } else {
            $this.CursorPosition = 0
        }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "PressEnd" -Value {
        Param([bool]$Shift = $false, [bool]$Ctrl = $false)
        if ($Shift) {
            if ($null -eq $this.SelectionAnchor) { $this.SelectionAnchor = $this.CursorPosition }
        } else {
            $this.ClearSelection()
        }
        if ($this.MultiLine -and -not $Ctrl) {
            $oCursor = $this.GetCursorLineColumn()
            $aLines = $this.GetLines()
            $this.CursorPosition = $this.GetFlatPosition($oCursor.Line, $aLines[$oCursor.Line].Length)
        } else {
            $this.CursorPosition = $this.Text.Length
        }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "PressSelectAll" -Value {
        $this.SelectionAnchor = 0
        $this.CursorPosition = $this.Text.Length
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "PressCopy" -Value {
        if ($this.PasswordChar) { return }
        if (-not $this.HasSelection()) { return }
        Set-Clipboard -Value $this.GetSelectedText()
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "PressPaste" -Value {
        $sClipboard = Get-Clipboard -ErrorAction SilentlyContinue
        if (-not $sClipboard) { return }
        if ($this.MultiLine) {
            # Preserve newlines, normalize line endings
            $sClipboard = ($sClipboard -join "`n").Replace("`r`n", "`n").Replace("`r", "`n")
        } else {
            # Flatten to single line
            $sClipboard = ($sClipboard -join "").Replace("`r", "").Replace("`n", "")
        }
        # Delete selection first if any
        $this.DeleteSelection() | Out-Null
        # Insert at cursor
        $sPrefix = if ($this.CursorPosition -gt 0) { $this.Text.Substring(0, $this.CursorPosition) } else { "" }
        $sSuffix = if ($this.CursorPosition -lt $this.Text.Length) { $this.Text.Substring($this.CursorPosition) } else { "" }
        $this.Text = $sPrefix + $sClipboard + $sSuffix
        $this.CursorPosition += $sClipboard.Length
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "PressCut" -Value {
        if ($this.PasswordChar) { return }
        if (-not $this.HasSelection()) { return }
        $this.PressCopy()
        $this.DeleteSelection() | Out-Null
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "GetHistory" -Value {
        if ($null -eq $Global:CLIDialogHistory) {
            $Global:CLIDialogHistory = @{}
        }
        if ($Global:CLIDialogHistory.ContainsKey($this.Name)) {
            return ,$Global:CLIDialogHistory[$this.Name]
        }
        return ,@()
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "SaveToHistory" -Value {
        if ($this.PasswordChar) { return }
        if (-not $this.Text -or $this.Text.Length -eq 0) { return }
        if ($null -eq $Global:CLIDialogHistory) {
            $Global:CLIDialogHistory = @{}
        }
        if (-not $Global:CLIDialogHistory.ContainsKey($this.Name)) {
            $Global:CLIDialogHistory[$this.Name] = [System.Collections.ArrayList]@()
        }
        $aHistory = $Global:CLIDialogHistory[$this.Name]
        if ($aHistory.Count -eq 0 -or $aHistory[$aHistory.Count - 1] -ne $this.Text) {
            $aHistory.Add($this.Text) | Out-Null
        }
        $this.HistoryIndex = -1
        $this.HistoryCurrentText = $null
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "PressHistoryUp" -Value {
        $aHistory = $this.GetHistory()
        if ($aHistory.Count -eq 0) { return }
        if ($this.HistoryIndex -eq -1) {
            $this.HistoryCurrentText = $this.Text
            $this.HistoryIndex = $aHistory.Count - 1
        } elseif ($this.HistoryIndex -gt 0) {
            $this.HistoryIndex--
        } else {
            return
        }
        $this.Text = [string]$aHistory[$this.HistoryIndex]
        $this.CursorPosition = $this.Text.Length
        $this.ClearSelection()
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "PressHistoryDown" -Value {
        if ($this.HistoryIndex -eq -1) { return }
        $aHistory = $this.GetHistory()
        if ($this.HistoryIndex -lt $aHistory.Count - 1) {
            $this.HistoryIndex++
            $this.Text = [string]$aHistory[$this.HistoryIndex]
        } else {
            $this.HistoryIndex = -1
            $this.Text = [string]$this.HistoryCurrentText
            $this.HistoryCurrentText = $null
        }
        $this.CursorPosition = $this.Text.Length
        $this.ClearSelection()
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "PressUp" -Value {
        if ($this.MultiLine) {
            $oCursor = $this.GetCursorLineColumn()
            if ($oCursor.Line -gt 0) {
                $this.CursorPosition = $this.GetFlatPosition($oCursor.Line - 1, $oCursor.Column)
                $this.ClearSelection()
                $this.EnsureCursorVisible()
                return
            }
        }
        $hResult = @{
            Key = [System.ConsoleKeyInfo]::new(0, [System.ConsoleKey]::UpArrow, $false, $false, $false)
            Options = if ($this.MultiLine) { $this.GetCursorLineColumn().Column } else { $this.CursorPosition }
        }
        return $hResult
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "PressDown" -Value {
        if ($this.MultiLine) {
            $oCursor = $this.GetCursorLineColumn()
            $aLines = $this.GetLines()
            if ($oCursor.Line -lt $aLines.Count - 1) {
                $this.CursorPosition = $this.GetFlatPosition($oCursor.Line + 1, $oCursor.Column)
                $this.ClearSelection()
                $this.EnsureCursorVisible()
                return
            }
        }
        $hResult = @{
            Key = [System.ConsoleKeyInfo]::new(0, [System.ConsoleKey]::DownArrow, $false, $false, $false)
            Options = if ($this.MultiLine) { $this.GetCursorLineColumn().Column } else { $this.CursorPosition }
        }
        return $hResult
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "PressKey" -Value {
        Param(
            [System.ConsoleKeyInfo]$KeyInfo
        )
        $this.LastTestedText = $this.Text
        $bShift = ($KeyInfo.Modifiers -band [System.ConsoleModifiers]::Shift) -eq [System.ConsoleModifiers]::Shift
        $bCtrl = ($KeyInfo.Modifiers -band [System.ConsoleModifiers]::Control) -eq [System.ConsoleModifiers]::Control

        if ([System.Char]::IsControl($KeyInfo.KeyChar)) {
            # Handle Ctrl+key combinations
            if ($bCtrl) {
                switch ($KeyInfo.Key) {
                    ([System.ConsoleKey]::A) { return $this.PressSelectAll() }
                    ([System.ConsoleKey]::C) { return $this.PressCopy() }
                    ([System.ConsoleKey]::V) { return $this.PressPaste() }
                    ([System.ConsoleKey]::X) { return $this.PressCut() }
                    ([System.ConsoleKey]::UpArrow) { return $this.PressHistoryUp() }
                    ([System.ConsoleKey]::DownArrow) { return $this.PressHistoryDown() }
                }
            }

            switch ($KeyInfo.Key) {
                ([System.ConsoleKey]::LeftArrow) { return $this.PressLeft($bShift) }
                ([System.ConsoleKey]::RightArrow) { return $this.PressRight($bShift) }
                ([System.ConsoleKey]::UpArrow) { return $this.PressUp() }
                ([System.ConsoleKey]::DownArrow) { return $this.PressDown() }
                ([System.ConsoleKey]::Home) { return $this.PressHome($bShift, $bCtrl) }
                ([System.ConsoleKey]::End) { return $this.PressEnd($bShift, $bCtrl) }
                ([System.ConsoleKey]::Backspace) { return $this.PressBackspace() }
                ([System.ConsoleKey]::Delete) { return $this.PressDelete() }
                ([System.ConsoleKey]::Enter) {
                    if ($this.MultiLine) {
                        $this.DeleteSelection() | Out-Null
                        $sPrefix = if ($this.CursorPosition -gt 0) { $this.Text.Substring(0, $this.CursorPosition) } else { "" }
                        $sSuffix = if ($this.CursorPosition -lt $this.Text.Length) { $this.Text.Substring($this.CursorPosition) } else { "" }
                        $this.Text = $sPrefix + "`n" + $sSuffix
                        $this.CursorPosition++
                        $this.EnsureCursorVisible()
                        return
                    }
                    return $KeyInfo
                }
                default {
                    return $KeyInfo
                }
            }
        } else {
            # Regular character input: replace selection if any, then insert
            $this.DeleteSelection() | Out-Null

            if ($this.CursorPosition -eq $this.Text.ToString().Length) {
                $this.Text += $KeyInfo.KeyChar
                $this.CursorPosition++
            } else {
                $sPrefix = if ($this.CursorPosition -eq 0) {
                    ""
                } else {
                    $this.Text.Substring(0, $this.CursorPosition)
                }
                $sSuffix = if ($this.CursorPosition -lt $this.Text.Length) {
                    $this.Text.Substring($this.CursorPosition)
                } else {
                    ""
                }
                $this.Text = $sPrefix + $KeyInfo.KeyChar + $sSuffix
                $this.CursorPosition++
            }
        }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "SetCursorPosition" -Value {
        Param(
            [int]$Position
        )
        $this.ClearSelection()
        if ($Position -lt 0) {
            $this.CursorPosition = 0
        } elseif ($Position -gt $this.Text.Length) {
            $this.CursorPosition = $this.Text.Length
        } else {
            $this.CursorPosition = $Position
        }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "SetCursorPositionAtLine" -Value {
        Param(
            [int]$Line,
            [int]$Column
        )
        $this.ClearSelection()
        $aLines = $this.GetLines()
        # -1 means last line
        if ($Line -lt 0) { $Line = $aLines.Count - 1 }
        if ($Line -ge $aLines.Count) { $Line = $aLines.Count - 1 }
        $this.CursorPosition = $this.GetFlatPosition($Line, $Column)
        $this.EnsureCursorVisible()
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "GetTextHeight" -Value {
        if ($this.MultiLine) {
            return $this.GetCurrentVisibleLineCount()
        }
        return 1
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "GetTextWidth" -Value {
        return $this.Prefix.Length + $this.Header.Length + $this.HeaderSeparator.Length + $this.Text.Length
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "Reset" -Value {
        $this.Text = $this.OriginalText
        $this.ClearSelection()
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "GetValue" -Value {
        if ($this.PasswordChar) {
            return $this.Text | ConvertTo-SecureString -AsPlainText -Force
        } else {
            if ($this.ValueConvertFunction) {
                return . $this.ValueConvertFunction $this.Text
            } else {
                return $this.Text
            }
        }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "IsDynamicObject" -Value {
        return $true
    }

    return $hResult
}
