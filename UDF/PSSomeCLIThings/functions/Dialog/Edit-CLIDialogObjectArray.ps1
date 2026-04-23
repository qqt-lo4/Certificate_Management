function Edit-CLIDialogObjectArray {
    <#
    .SYNOPSIS
        Interactive editor for a list of objects with add, remove, and reorder capabilities.

    .DESCRIPTION
        Uses Select-CLIDialogObjectInArray as the main display component with action buttons
        (Add, Remove, Move Up, Move Down) passed as OtherMenuItems. Actions operate on the
        currently focused item without requiring a separate selection step.
        Returns the final array when OK is pressed, or $null on Cancel.

    .PARAMETER Header
        Header text for the dialog.

    .PARAMETER DisplayColumns
        Property names to display in the table. Other properties are stored but hidden.

    .PARAMETER ItemProperties
        OrderedDictionary schema for Read-CLIDialogHashtable when adding items.

    .PARAMETER DefaultItems
        Initial items to pre-populate.

    .PARAMETER SeparatorColor
        Color for separators. Default: Cyan.

    .OUTPUTS
        [PSCustomObject[]] or $null on cancel.

    .EXAMPLE
        $items = Edit-CLIDialogObjectArray -Header "Shares" `
            -DisplayColumns @("Type", "Server", "Path") `
            -ItemProperties ([ordered]@{
                "Type"   = @{ Regex = "^(DFS|Filer)$" }
                "Server" = @{}
                "Path"   = @{}
            })

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-04-18) - Loïc Ade
            - Initial version using Select-CLIDialogObjectInArray with PassthroughActions
    #>
    [CmdletBinding()]
    Param(
        [string]$Header = "Edit items",
        [string[]]$DisplayColumns,
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary]$ItemProperties,
        [object[]]$DefaultItems,
        [System.ConsoleColor]$SeparatorColor = (Get-CLIDialogTheme SeparatorColor)
    )

    $aItems = [System.Collections.ArrayList]::new()
    if ($DefaultItems) {
        foreach ($oItem in $DefaultItems) {
            if ($oItem -is [System.Collections.IDictionary]) {
                [void]$aItems.Add([PSCustomObject]$oItem)
            } else {
                [void]$aItems.Add($oItem)
            }
        }
    }

    $iFocusIndex = -1

    while ($true) {
        $aOrganizationItems = @(
            New-CLIDialogButton -Text "&Add" -Add
        )
        if ($aItems.Count -gt 0) {
            $aOrganizationItems += New-CLIDialogSpace
            $aOrganizationItems += New-CLIDialogButton -Text "&Edit" -Edit
            $aOrganizationItems += New-CLIDialogSpace
            $aOrganizationItems += New-CLIDialogButton -Text "&Remove" -Remove
        }
        if ($aItems.Count -gt 1) {
            $aOrganizationItems += New-CLIDialogSpace
            $aOrganizationItems += New-CLIDialogButton -Text "Move &Up" -MoveUp
            $aOrganizationItems += New-CLIDialogSpace
            $aOrganizationItems += New-CLIDialogButton -Text "Move &Down" -MoveDown
        }

        $aMenuItems = @(
            New-CLIDialogObjectsRow -Row $aOrganizationItems -Header "Edit list"
            New-CLIDialogObjectsRow -Row @(
                New-CLIDialogButton -Text "&OK" -Validate
                New-CLIDialogSpace
                New-CLIDialogButton -Text "&Cancel" -Cancel
            ) -InvisibleHeader
        )

        # Build Select parameters
        $hSelectParams = @{
            Objects                          = if ($aItems.Count -gt 0) { @($aItems) } else { $null }
            SelectedColumns                  = $DisplayColumns
            SelectHeaderMessage              = "$Header ($($aItems.Count) items)"
            HeaderTextInSeparator            = $true
            SeparatorColor                   = $SeparatorColor
            OtherMenuItems                   = $aMenuItems
            DontShowPageNumberWhenOnlyOnePage = $true
            PassthroughActions               = @("Add", "Edit", "Remove", "MoveUp", "MoveDown", "Validate", "Cancel")
        }
        if ($aItems.Count -eq 0) {
            $hSelectParams.EmptyArrayMessage = "  (no items)"
        }
        if ($iFocusIndex -ge 0) {
            $hSelectParams.DefaultFocusedIndex = $iFocusIndex
        }

        $oResult = Select-CLIDialogObjectInArray @hSelectParams

        if (-not $oResult -or $oResult.Action -eq "Cancel") {
            return $null
        }

        $sAction = if ($oResult.Type -eq "Value") { "Edit" } else { $oResult.Action }

        switch ($sAction) {
            "Validate" {
                return @($aItems)
            }
            "Add" {
                $hNewItem = Read-CLIDialogHashtable -Properties $ItemProperties `
                    -Header "Add new item" -AllowCancel
                if ($hNewItem) {
                    $iInsertAt = if ($oResult.FocusedIndex -ge 0 -and $aItems.Count -gt 0) {
                        [Math]::Min($oResult.FocusedIndex + 1, $aItems.Count)
                    } else {
                        $aItems.Count
                    }
                    $aItems.Insert($iInsertAt, [PSCustomObject]$hNewItem)
                    $iFocusIndex = $iInsertAt
                }
            }
            "Edit" {
                $iIdx = if ($oResult.Type -eq "Value") {
                    $aItems.IndexOf($oResult.Value)
                } else {
                    $oResult.FocusedIndex
                }
                if ($iIdx -ge 0 -and $iIdx -lt $aItems.Count) {
                    $oCurrent = $aItems[$iIdx]
                    $hEditProperties = [ordered]@{}
                    foreach ($sKey in $ItemProperties.Keys) {
                        $hClone = @{}
                        foreach ($sSubKey in $ItemProperties[$sKey].Keys) {
                            $hClone[$sSubKey] = $ItemProperties[$sKey][$sSubKey]
                        }
                        $oValue = $oCurrent.$sKey
                        if ($null -ne $oValue) {
                            $hClone.Text = "$oValue"
                        }
                        $hEditProperties[$sKey] = $hClone
                    }
                    $hEdited = Read-CLIDialogHashtable -Properties $hEditProperties `
                        -Header "Edit item" -AllowCancel
                    if ($hEdited) {
                        $aItems[$iIdx] = [PSCustomObject]$hEdited
                        $iFocusIndex = $iIdx
                    }
                }
            }
            "Remove" {
                if ($aItems.Count -gt 0 -and $oResult.FocusedIndex -ge 0) {
                    $aItems.RemoveAt($oResult.FocusedIndex)
                    # Keep focus at same position, or move to last item if was at end
                    $iFocusIndex = if ($aItems.Count -eq 0) { -1 }
                        elseif ($oResult.FocusedIndex -ge $aItems.Count) { $aItems.Count - 1 }
                        else { $oResult.FocusedIndex }
                }
            }
            "MoveUp" {
                $iIdx = $oResult.FocusedIndex
                if ($iIdx -gt 0 -and $iIdx -lt $aItems.Count) {
                    $oTemp = $aItems[$iIdx]
                    $aItems.RemoveAt($iIdx)
                    $aItems.Insert($iIdx - 1, $oTemp)
                    $iFocusIndex = $iIdx - 1
                }
            }
            "MoveDown" {
                $iIdx = $oResult.FocusedIndex
                if ($iIdx -ge 0 -and $iIdx -lt $aItems.Count - 1) {
                    $oTemp = $aItems[$iIdx]
                    $aItems.RemoveAt($iIdx)
                    $aItems.Insert($iIdx + 1, $oTemp)
                    $iFocusIndex = $iIdx + 1
                }
            }
        }
    }
}
