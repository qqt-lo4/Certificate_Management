function Read-CLIDialogArray {
    <#
    .SYNOPSIS
        Reads a multi-line list from user input via a multi-line textbox dialog.

    .DESCRIPTION
        Displays an interactive CLI dialog with a multi-line textbox for entering
        multiple items (one per line). Supports regex validation per line,
        regex-based grouping of results, and Cancel/Back buttons for wizard integration.

    .PARAMETER Header
        Header text displayed above the textbox. Default: "Please enter a list of items (one per line):"

    .PARAMETER TextBoxHeader
        Label of the multi-line textbox field. Default: "Items"

    .PARAMETER VisibleLines
        Maximum visible lines in the multi-line textbox. Default: 8

    .PARAMETER DefaultValue
        Default text to pre-populate in the textbox. Lines are separated by newline characters.

    .PARAMETER Regex
        Regex pattern to validate each non-empty line against. If specified, the dialog
        loops until all lines are valid or the user cancels.

    .PARAMETER ValidationScript
        Scriptblock to validate each non-empty line. Receives the line as parameter.
        Takes precedence over Regex if both are specified.

    .PARAMETER GroupByProperties
        An ordered dictionary defining regex-based grouping. Each key is a group name
        with a value containing a Regex property and an optional IgnoreOtherRegex property.
        When specified, the result is a hashtable with keys for each group plus "Other".

    .PARAMETER SeparatorColor
        Color for separators. Default: from theme.

    .PARAMETER AllowCancel
        Switch parameter. Adds a Cancel button.

    .PARAMETER AllowBack
        Switch parameter. Adds a Back button.

    .OUTPUTS
        [string[]] when GroupByProperties is not specified — array of non-empty lines.
        [hashtable] when GroupByProperties is specified — grouped results.
        DialogResult.Action.Cancel or DialogResult.Action.Back on user cancellation.

    .EXAMPLE
        $items = Read-CLIDialogArray -Header "Enter DNS names:" -TextBoxHeader "DNS"
        # Returns array of strings

    .EXAMPLE
        $grouped = Read-CLIDialogArray -Header "Enter DNS and IP SANs:" -GroupByProperties ([ordered]@{
            IP = @{ Regex = '^\d+\.\d+\.\d+\.\d+$'; IgnoreOtherRegex = $true }
            DNS = @{ Regex = '^[a-zA-Z0-9.*-]+$' }
        }) -AllowBack

    .NOTES
        Author: Loïc Ade
        Version: 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-04-06 - Loïc Ade
            - Initial release
            - Multi-line textbox for list input
            - Regex and scriptblock validation per line
            - GroupByProperties for regex-based categorization
            - Cancel and Back support for wizard integration
    #>
    Param(
        [string]$Header = "Please enter a list of items (one per line):",
        [string]$TextBoxHeader = "Items",
        [string]$HintMessage,
        [int]$VisibleLines = 6,
        [string]$DefaultValue,
        [string]$Regex,
        [scriptblock]$ValidationScript,
        [System.Collections.Specialized.OrderedDictionary]$GroupByProperties,
        [System.ConsoleColor]$SeparatorColor = (Get-CLIDialogTheme "SeparatorColor"),
        [switch]$AllowCancel,
        [switch]$AllowBack
    )

    $hTextboxParams = @{
        Header = $TextBoxHeader
        Name = $TextBoxHeader
        MultiLine = $true
        VisibleLines = $VisibleLines
        Prefix = "  "
        FocusedPrefix = "> "
    }
    if ($DefaultValue) {
        $hTextboxParams.Text = $DefaultValue
    }
    # Per-line validation via scriptblock wrapping the Regex or ValidationScript
    if ($Regex) {
        $sLineRegex = $Regex
        $hTextboxParams.ValidationScript = {
            param($text)
            $aLines = $text.Split("`n")
            foreach ($sLine in $aLines) {
                if ($sLine.Length -gt 0 -and $sLine -notmatch $sLineRegex) {
                    return $false
                }
            }
            return $true
        }.GetNewClosure()
        $hTextboxParams.ValidationErrorReason = "each line must match: $Regex"
    } elseif ($ValidationScript) {
        $sbLineValidation = $ValidationScript
        $hTextboxParams.ValidationScript = {
            param($text)
            $aLines = $text.Split("`n")
            foreach ($sLine in $aLines) {
                if ($sLine.Length -gt 0 -and -not (. $sbLineValidation $sLine)) {
                    return $false
                }
            }
            return $true
        }.GetNewClosure()
    }

    $aDialogLines = @(
        New-CLIDialogSeparator -AutoLength -Text $Header -ForegroundColor $SeparatorColor
    )
    if ($HintMessage) {
        $aDialogLines += New-CLIDialogText -Text $HintMessage -ForegroundColor (Get-CLIDialogTheme "HintColor") -AddNewLine
    }
    $aDialogLines += @(
        New-CLIDialogTextBox @hTextboxParams
        New-CLIDialogSeparator -AutoLength -ForegroundColor $SeparatorColor
    )
    $aButtons = @(
        New-CLIDialogButton -Text "&Ok" -Validate
    )
    if ($AllowCancel) {
        $aButtons += New-CLIDialogButton -Text "&Cancel" -Cancel
    }
    if ($AllowBack) {
        $aButtons += New-CLIDialogButton -Back -Text "&Back"
    }
    $aDialogLines += New-CLIDialogObjectsRow -Header " " -Prefix "  " -FocusedPrefix "> " -HeaderSeparator "  " -Row $aButtons

    $oDialogResult = Invoke-CLIDialog -InputObject $aDialogLines -Validate -ErrorDetails

    # Handle Cancel or Back
    if ($oDialogResult.Action -eq "Cancel") {
        return New-DialogResultAction -Action "Cancel"
    }
    if ($oDialogResult.Action -eq "Back") {
        return New-DialogResultAction -Action "Back"
    }

    # Parse result: split text into non-empty lines
    $sText = $oDialogResult.DialogResult.Form.GetValue()[$TextBoxHeader]
    $aLines = $sText.Split("`n") | Where-Object { $_.Trim().Length -gt 0 } | ForEach-Object { $_.Trim() }

    if ($GroupByProperties) {
        $hResult = @{}
        foreach ($sKey in $GroupByProperties.Keys) {
            $hResult.$sKey = @()
        }
        $hResult.Other = @()
        foreach ($sLine in $aLines) {
            $bFoundRegex = $false
            foreach ($sKey in $GroupByProperties.Keys) {
                if ($sLine -match $GroupByProperties.$sKey.Regex) {
                    $bFoundRegex = $true
                    $hResult.$sKey += $sLine
                    if ($GroupByProperties.$sKey.IgnoreOtherRegex) {
                        break
                    }
                }
            }
            if (-not $bFoundRegex) {
                $hResult.Other += $sLine
            }
        }
        return $hResult
    } else {
        return @($aLines)
    }
}
