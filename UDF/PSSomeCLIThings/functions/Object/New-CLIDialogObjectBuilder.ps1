function New-CLIDialogObjectBuilder {
    <#
    .SYNOPSIS
        Builds a stateful, paginated dialog builder for an object.

    .DESCRIPTION
        Part of the convention-driven object dialog engine. Resolves, by naming
        convention, the header, property list, content table and menu for an object,
        and returns a builder object that holds the pagination state and exposes the
        navigation methods used by Show-CLIDialogObject:

            GetDialog()              build the dialog for the current page
            IsPaginatedDialog()      whether the content spans more than one page
            GetPageBounds()          first/last page and page count
            CanPreviousPage()        whether a previous page exists
            CanNextPage()            whether a next page exists
            PreviousPage()           move to the previous page
            NextPage()               move to the next page
            Refresh($Object)         reload content for a (possibly new) object

        The convention function names it looks up are documented in the NOTES of
        Get-CLIDialogObject.

    .PARAMETER Object
        The object to build a dialog for.

    .PARAMETER FunctionFriendlyName
        Optional friendly name of the requested function/view (e.g. "All Info").
        When omitted, the type default property function (if any) is used.

    .PARAMETER ItemsPerPage
        Number of content rows per page. Defaults to 15.

    .OUTPUTS
        A builder hashtable enriched with the navigation script methods listed above.

    .NOTES
        Author  : Loïc Ade
        Version : 1.1.0

        Dependencies:
            Get-Function                 (PSSomeCoreThings)
            Get-PaginatedArrayBoundaries (PSSomeDataThings)
            Get-CLIObjectPropertyList    (PSSomeCLIThings)

        CHANGELOG:

        Version 1.1.0 - 2026-06-17 - Loïc Ade
            - The displayed property list now comes from Get-CLIObjectPropertyList
              (registry-driven, with legacy Get-<Type>[-<Func>]_ObjectProperties
              fallback), mirroring the dual-mode menu. The inline legacy property
              function resolution was removed.

        Version 1.0.0 - 2026-06-14 - Loïc Ade
            - Initial release. Extracted unchanged from the Hotline_tool script
              (formerly New-ObjectDialogBuilder) into PSSomeCLIThings; the internal
              dialog build now calls Get-CLIDialogObject.
            - Dual-mode menu with fallback: the object menu comes from the registry
              (New-CLIDialogMenuFromRegistry) when it yields rows, otherwise from the
              legacy Get-<Type>_ProjectMenu. No registered button => legacy behaviour.
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$Object,
        [Parameter(Position = 1)]
        [string]$FunctionFriendlyName,
        [int]$ItemsPerPage = 15
    )
    $sFriendlyTypeName = $Object.PSTypeNames[0]
    $sType = $sFriendlyTypeName.Replace(" ", "")
    $sFriendlyTypeName = $sFriendlyTypeName.Replace("_", " ")
    $sFunction = $FunctionFriendlyName.Replace(" ", "")
    # The menu uses the requested view (empty for the base view), like the legacy
    # menu resolution below - NOT the default property that $sFunction is reassigned
    # to further down (that default only drives properties/content).
    $sMenuFunction = $sFunction
    $f = Get-Function "Get-$sType`_ObjectName"
    $sHeaderPrefix = if ($f) {
        . $f $Object
    } elseif ($Object.Name) {
        $Object.Name
    } else {
        $Object.ToString()
    }
    $sHeader = if ($Object.Category) {
        $sHeaderPrefix + " ($($Object.Category))"
    } elseif ($sFunction) {
        $sHeaderPrefix + " ($FunctionFriendlyName)"
    } else {
        $sHeaderPrefix + " ($sFriendlyTypeName)"
    }
    $fObjectMenu = if ($sFunction) {
        $f = Get-Function "Get-$sFunction`_ProjectMenu"
        if ($f) {
            $f
        } else {
            Get-Function "Get-$sType-$sFunction`_ProjectMenu"
        }
    } else {
        Get-Function "Get-$sType`_ProjectMenu"
    }
    $sFunction = if ($sFunction) {
        $sFunction
    } else {
        $f = Get-Function "Get-$sType`_DefaultProperty"
        if ($f) {
            . $f
        } else {
            ""
        }
    }
    $f = Get-Function "Get-$sType-$sFunction`_ObjectContent"
    $fObjectContent = if ($f) {
        $f
    } else {
        Get-Function "Get-$sType`_ObjectContent"
    }
    # Property list comes from the registry (with legacy Get-<Type>[-<Func>]_ObjectProperties
    # fallback) via the same view token used for the menu.
    $aObjectProperties = Get-CLIObjectPropertyList -Object $Object -Function $sMenuFunction
    # Dual mode with fallback (no concatenation, to avoid duplicates): use the
    # registry-driven menu when it produces rows, otherwise fall back to the legacy
    # Get-<Type>_ProjectMenu. A type is therefore either fully registry-driven or
    # fully legacy; with no registered button the behaviour is the legacy one.
    $oRegistryMenu = New-CLIDialogMenuFromRegistry -Object $Object -Function $sMenuFunction
    $oObjectMenu = if (@($oRegistryMenu).Count -gt 0) {
        $oRegistryMenu
    } elseif ($fObjectMenu) {
        . $fObjectMenu $Object
    } else {
        $null
    }
    $oObjectContent = if ($fObjectContent) { . $fObjectContent $Object } else { $null }
    $bPaginatedDialog = ($oObjectContent -and ($oObjectContent.Value.Count -gt $ItemsPerPage))

    $hResult = @{
        Header = $sHeader
        Object = $Object
        ObjectProperties = $aObjectProperties
        ObjectContent = $oObjectContent
        Menu = $oObjectMenu
        PaginatedDialog = $bPaginatedDialog
        Functions = @{
            ObjectProperties = $null   # property list now comes from Get-CLIObjectPropertyList
            ObjectContent = $fObjectContent
            Menu = $fObjectMenu
        }
        Page = 0
        ItemsPerPage = $ItemsPerPage
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "IsPaginatedDialog" -Value {
        return ($this.ObjectContent -and ($this.ObjectContent.Value.Count -gt $this.ItemsPerPage))
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "GetPageBounds" -Value {
        return Get-PaginatedArrayBoundaries -Objects $this.ObjectContent.Value -ItemsPerPage $this.ItemsPerPage -Page 0
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "CanPreviousPage" -Value {
        return $this.Page -gt 0
    }
    $hResult | Add-Member -MemberType ScriptMethod -Name "CanNextPage" -Value {
        return $this.Page -lt ($this.GetPageBounds()).LastPage
    }
    $hResult | Add-Member -MemberType ScriptMethod -Name "PreviousPage" -Value {
        if ($this.CanPreviousPage()) {
            $this.Page -= 1
        } else {
            throw "Can't go to previous page"
        }
    }
    $hResult | Add-Member -MemberType ScriptMethod -Name "NextPage" -Value {
        if ($this.CanNextPage()) {
            $this.Page += 1
        } else {
            throw "Can't go to next page"
        }
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "GetDialog" -Value {
        $hGetDialogArgs = @{
            Header = $this.Header
            Object = $this.Object
            ExpandPropertyPage = $this.Page
            ExpandPropertyItemsPerPage = $this.ItemsPerPage
        }
        $hGetDialogArgs.PauseAfterContentSeparator = if ($this.ObjectContent -and $this.ObjectContent.Value) {
            $false
        } else {
            if ($this.ObjectProperties) {
                -not $this.IsPaginatedDialog()
            } else {
                $false
            }
        }
        if ($this.ObjectProperties) { $hGetDialogArgs.ObjectProperty = $this.ObjectProperties }
        if ($this.ObjectContent) { $hGetDialogArgs.ObjectContent = $this.ObjectContent }
        if ($this.Menu) { $hGetDialogArgs.ObjectMenu = $this.Menu }
        $oDialog = Get-CLIDialogObject @hGetDialogArgs
        return $oDialog
    }

    $hResult | Add-Member -MemberType ScriptMethod -Name "Refresh" -Value {
        Param(
            [Parameter(Mandatory, Position = 0)]
            [object]$Object
        )
        $this.Object = $Object
        $f = $this.Functions.ObjectContent
        $this.ObjectContent = if ($f) { . $f $Object } else { $null }
        $this.ExpandPropertyPage = 0
    }

    return $hResult
}
