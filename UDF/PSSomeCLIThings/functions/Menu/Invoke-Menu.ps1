function Invoke-Menu {
    <#
    .SYNOPSIS
        Displays and executes an interactive menu with support for nested sub-menus.

    .DESCRIPTION
        Renders a menu object and handles user interaction through a CLI dialog interface.
        Supports hierarchical menu structures, menu item execution, sub-menu navigation,
        and menu actions (Back, Exit). Tracks recursion depth for proper navigation.

    .PARAMETER Menu
        Menu object created with New-Menu. Must have Type = "menu".

    .PARAMETER Depth
        Current depth level in menu hierarchy. Default: 0 (root menu).
        Used internally for recursive sub-menu navigation.

    .EXAMPLE
        $menu = New-Menu -Text "Main Menu" -Content @(
            New-MenuItem -Text "Option 1" -Content { Write-Host "Selected" }
        ) -OtherMenuItems @(New-MenuAction -Text "Exit" -Exit)
        Invoke-Menu -Menu $menu

    .NOTES
        Author: Loïc Ade
        Version: 1.1.0

        CHANGELOG:

        Version 1.1.0 - 2026-04-04 - Loïc Ade
            - Added support for SeparatorWidthMode from New-Menu

        Version 1.0.0 - 2025-11-22 - Loïc Ade
            - Initial release
    #>
    Param(
        [Parameter(Position = 0)]
        [object]$Menu,
        [int]$Depth = 0
    )
    Begin {
        if ($Menu.Type -ne "menu") {
            throw "Object is not a menu"
        }
        $aDialogLines = @()
        $hSeparatorArgs = @{ ForegroundColor = $Menu.SeparatorColor }
        if ($Menu.SeparatorWidthMode -eq "FullWidth") {
            $hSeparatorArgs.FullWidth = $true
        } else {
            $hSeparatorArgs.AutoLength = $true
        }
        if ($Menu.Text) {
            $aDialogLines += New-CLIDialogSeparator @hSeparatorArgs -Text ($Menu.Text -replace "&", "")
        }
        $iRecommended = 0
        $i = 0
        foreach ($menuitem in $Menu.Content) {
            $oNewButton = $menuitem.ConvertToButton()
            if ($menuitem.Recommended) {
                $iRecommended = $i
            }
            $oNewButton.AddNewLine = $true
            $aDialogLines += $oNewButton
            $i++
        }
        if ($Menu.OtherMenuItems) {
            $aDialogLines += New-CLIDialogSeparator @hSeparatorArgs
            foreach ($menuitem in $Menu.OtherMenuItems) {
                $oNewButton = $menuitem.ConvertToButton()
                $oNewButton.AddNewLine = $true
                $aDialogLines += $oNewButton
            }
        }
        $aDialogLines += New-CLIDialogSeparator @hSeparatorArgs    
        $oDialog = New-CLIDialog -Rows $aDialogLines
        $oDialog.FocusedRow = $iRecommended
    }
    Process {
        while ($true) {
            $oDialogItem = Invoke-CLIDialog -InputObject $oDialog -Execute
            if ($null -eq $oDialogItem -or $null -eq $oDialogItem.Value) {
                continue
            }
            $oDialogResult = switch ($oDialogItem.Value.PSObject.TypeNames[0]) {
                "MenuAction" {
                    $sAction = $oDialogItem.Action
                    if ($sAction -eq "Exit") {
                        New-DialogResultAction -Action "Exit" -DialogResult $oDialogItem.Value
                    } else {
                        New-DialogResultAction -Action "Back" -DialogResult $oDialogItem.Value
                    }
                }
                "MenuItem" {
                    Invoke-Command -ScriptBlock $oDialogItem.Value.Content
                }
                "Menu" {
                    Invoke-Menu -Menu $oDialogItem.Value -Depth ($Depth + 1)
                }
            }
            if ($null -eq $oDialogResult) {
                continue
            }
            switch ($oDialogResult.PSObject.TypeNames[0]) {
                "DialogResult.Action.Exit" {
                    if ($Depth -eq 0) {
                        Exit
                    } else {
                        return $oDialogResult
                    }
                }
                "DialogResult.Action.Back" {
                    if ($oDialogResult.Depth -eq 0) {
                        $oDialogResult.Depth += 1
                        return $oDialogResult
                    }
                }
                default {
                    return $oDialogResult
                }
            }
            #return $oDialogResult
        }
    }
}