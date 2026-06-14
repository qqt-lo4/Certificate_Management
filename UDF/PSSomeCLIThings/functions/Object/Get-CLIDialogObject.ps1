function Get-CLIDialogObject {
    <#
    .SYNOPSIS
        Builds a CLI dialog form from an object's properties, content and menu.

    .DESCRIPTION
        Assembles a complete CLI dialog (header separator, property list, optional
        paginated content table, object menu and footer menu) from a single object.
        This is the rendering layer of the convention-driven object dialog engine;
        it is normally fed by New-CLIDialogObjectBuilder and driven by
        Show-CLIDialogObject, but can be called directly.

        Property enrichment is convention-based: for each PSTypeName of the object
        (hierarchy order, first match wins) the engine looks for a function named
        Add-<Type>Properties and, if found, runs it with the requested property list
        before selecting the values to display. This lets sparse objects (such as AD
        objects) load exactly the properties about to be shown.

        The default footer menu is injected, not hard-coded: when -OtherMenuItems is
        not supplied, the engine appends pagination/refresh controls and the menu
        returned by the provider registered with Set-CLIDialogDefaultMenu. The module
        therefore stays free of any project-specific menu.

    .PARAMETER Header
        Text shown in the top separator of the dialog.

    .PARAMETER SeparatorColor
        Foreground color used for the separators. Defaults to Blue.

    .PARAMETER Object
        The object to render.

    .PARAMETER ObjectProperty
        Property descriptors (hashtables with at least N/E keys, plus optional flags
        such as HideIfEmpty) describing which properties to display and how.

    .PARAMETER PropertiesContentSeparator
        Character used for the inner separators between sections. Defaults to "-".

    .PARAMETER ObjectContent
        Optional content descriptor (Value, Properties, Sort, FriendlyPropertyName,
        PropertyName, EmptyMessage) rendered as a paginated table below the
        properties.

    .PARAMETER ExpandPropertyPage
        Zero-based page index of the content table to render.

    .PARAMETER ExpandPropertyItemsPerPage
        Number of content rows per page. Defaults to 15.

    .PARAMETER PauseAfterContentSeparator
        When set, the separator below the content waits for a key press.

    .PARAMETER ObjectMenu
        Object-specific menu rows inserted between the content and the footer menu.

    .PARAMETER OtherMenuItems
        Explicit footer override. When supplied, it replaces the default footer
        entirely (pagination/refresh controls and the registered default menu are
        skipped).

    .OUTPUTS
        A CLI dialog object (PSTypeName "Dialog" or "PaginatedDialog").

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        Dependencies:
            Get-Function                (PSSomeCoreThings)
            Copy-Hashtable              (PSSomeDataThings)
            Get-PaginatedArrayBoundaries (PSSomeDataThings)
            Get-ArrayPage               (PSSomeDataThings)

        The full convention contract of the object dialog engine is documented in
        the NOTES of Show-CLIDialogObject (the engine entry point). The conventions
        this function relies on directly are Add-<Type>Properties (property
        enrichment) and the default footer menu injected via Set-CLIDialogDefaultMenu.

        CHANGELOG:

        Version 1.0.0 - 2026-06-14 - Loïc Ade
            - Initial release. Extracted from the Hotline_tool script (formerly
              Get-ObjectCustomDialog) into PSSomeCLIThings.
            - Decoupled the default footer menu: the hard-coded Get-GoTo_ProjectMenu
              call is replaced by the injected provider from Get-CLIDialogDefaultMenu.
            - Generalized property enrichment: the hard-coded, dead AD branch
              (which tested an undefined $ADObject variable) is replaced by a
              convention lookup of Add-<Type>Properties over the type hierarchy,
              and the enrichment is now separated from the property selection.
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Header,
        [System.ConsoleColor]$SeparatorColor = ([System.ConsoleColor]::Blue),
        [Parameter(Mandatory, Position = 1)]
        [object]$Object,
        [Parameter(Position = 2)]
        [object[]]$ObjectProperty,
        [string]$PropertiesContentSeparator = "-",
        [object]$ObjectContent,
        [int]$ExpandPropertyPage = 0,
        [int]$ExpandPropertyItemsPerPage = 15,
        [switch]$PauseAfterContentSeparator,
        [object[]]$ObjectMenu,
        [object[]]$OtherMenuItems
    )
    $aForm = @()
    $aForm += New-CLIDialogSeparator -Text $Header -AutoLength -ForegroundColor $SeparatorColor
    if ($ObjectProperty) {
        $hProperties = @{}
        $aProperties = $ObjectProperty | . { Process { $hProperties.$($_.N) = $_ ; @{N = $_.N; E = $_.E} } }

        # --- Enrichment: load type-specific properties when a provider exists ---
        #   Convention: Add-<Type>Properties (e.g. Add-ADObjectProperties). Looked
        # up over the whole type hierarchy, first match wins. Lets sparse objects
        # (such as AD objects) fetch exactly the properties about to be displayed.
        $oEnrichedObject = $Object
        foreach ($sPropertyTypeName in $Object.PSTypeNames) {
            $fAddProperties = Get-Function "Add-$($sPropertyTypeName.Replace(' ', ''))Properties"
            if ($fAddProperties) {
                $oEnrichedObject = $Object | & $fAddProperties -Properties $aProperties
                break
            }
        }

        # --- Selection: keep only the requested properties for display ---
        $oSelectedProperties = ($oEnrichedObject | Select-Object -Property $aProperties).PSObject.Properties

        foreach ($p in $oSelectedProperties) {
            $bHideIfEmpty = if ($hProperties.($p.name).ContainsKey("HideIfEmpty")) { $hProperties.($p.name)."HideIfEmpty" } else { $false }
            $sText = if ($null -eq $p.Value) { "" } else {
                $p.Value | ForEach-Object { $_.ToString().Trim() }
            }
            if (-not ($bHideIfEmpty -and ($sText -eq ""))) {
                $hArgs = @{
                    Header = $p.Name
                    Text = $sText
                }
                [hashtable]$hOtherProperties = Copy-Hashtable $hProperties.($p.Name)
                if ($hOtherProperties) {
                    $hOtherProperties.Remove("N")
                    $hOtherProperties.Remove("E")
                    $hOtherProperties.Remove("HideIfEmpty")
                    $hArgs += $hOtherProperties
                }
                $aForm += New-CLIDialogProperty @hArgs -HeaderSeparator " :  "
            }
        }
    }
    if ($ObjectContent) {
        if ($ObjectContent.Value) {
            if ($ObjectContent.Sort) {
                $ObjectContent.Value = $ObjectContent.Value | Sort-Object $ObjectContent.Sort
            }
            $oPageBounds = Get-PaginatedArrayBoundaries -Objects $ObjectContent.Value -ItemsPerPage $ExpandPropertyItemsPerPage -Page $ExpandPropertyPage
            $aItems = Get-ArrayPage -Objects $ObjectContent.Value -Page $ExpandPropertyPage -ItemsPerPage $ExpandPropertyItemsPerPage
            $bCanPreviousPage = $ExpandPropertyPage -gt 0
            $bCanNextPage = $ExpandPropertyPage -lt $oPageBounds.LastPage
            $sType = "PaginatedDialog"
            if ($ObjectProperty) {
                $aForm += New-CLIDialogSeparator -Char $PropertiesContentSeparator -AutoLength -PressKeyToContinue:$false -ForegroundColor $SeparatorColor -Text $ObjectContent.FriendlyPropertyName
            }
            $aForm += New-CLIDialogTableItems -Objects $aItems -Properties $ObjectContent.Properties
            $aForm += New-CLIDialogSeparator -Char $PropertiesContentSeparator -AutoLength -PressKeyToContinue:$PauseAfterContentSeparator -ForegroundColor $SeparatorColor -DrawArrows -DrawPageNumber -PageNumber $ExpandPropertyPage -PageCount $oPageBounds.PageCount
        } else {
            if ($oSelectedProperties) {
                $aForm += New-CLIDialogSeparator -Char $PropertiesContentSeparator -AutoLength -Text $ObjectContent.PropertyName -ForegroundColor $SeparatorColor
            }
            $sEmptyPropertyContent = if ($ObjectContent.EmptyMessage) {
                $ObjectContent.EmptyMessage
            } else {
                "Property $($ObjectContent.PropertyName) is empty for $($Object.Name)"
            }
            $aForm += New-CLIDialogText -Text $sEmptyPropertyContent -ForegroundColor Yellow -AddNewLine
            $aForm += New-CLIDialogSeparator -Char $PropertiesContentSeparator -AutoLength -ForegroundColor $SeparatorColor -DrawArrows -DrawPageNumber -PageNumber 0 -PageCount 1
        }
    } else {
        $sType = "Dialog"
        $aForm += New-CLIDialogSeparator -Char $PropertiesContentSeparator -AutoLength -ForegroundColor $SeparatorColor # -PressKeyToContinue:$PauseAfterContentSeparator
    }
    if ($ObjectMenu) {
        $aForm += $ObjectMenu
        $aForm += New-CLIDialogSeparator -AutoLength -Char $PropertiesContentSeparator -ForegroundColor $SeparatorColor
    }
    if ($OtherMenuItems) {
        $aForm += $OtherMenuItems
    } else {
        $aHiddenButtons = @()
        if ($ObjectContent.Value) {
            if ($bCanNextPage -or $bCanPreviousPage) {
                $aRow = @()
                if ($bCanPreviousPage) {
                    $aRow += New-CLIDialogButton -Text "&Previous" -Previous
                    $aHiddenButtons += New-CLIDialogButton -Text "Previous" -Keyboard PageUp -Previous
                }
                if ($bCanNextPage) {
                    $aRow += New-CLIDialogButton -Text "&Next" -Next
                    $aHiddenButtons += New-CLIDialogButton -Text "Next" -Keyboard PageDown -Next
                }
                $aForm += New-CLIDialogObjectsRow -Header "Page" -Row $aRow
            }
        }
        if ("Refresh" -in $Object.PSObject.Methods.Name) {
            $aHiddenButtons += New-CLIDialogButton -Text "Refresh" -Keyboard F5 -Refresh
        }
        # Default footer menu is injected by the host project via
        # Set-CLIDialogDefaultMenu, keeping this module project-agnostic.
        $fDefaultMenu = Get-CLIDialogDefaultMenu
        if ($fDefaultMenu) {
            $aForm += & $fDefaultMenu
        }
    }
    $hDialogArgs = @{
        Rows = $aForm
        ValidateObject = (New-CLIDialogButton -Text "OK" -Validate)
    }
    if ($aHiddenButtons.Count -ne 0) {
        $hDialogArgs.HiddenButtons = $aHiddenButtons
    }
    $oDialog = New-CLIDialog @hDialogArgs
    $oDialog.PSTypeNames.Insert(0, $sType)
    return $oDialog
}
