function Register-CLIObjectProperty {
    <#
    .SYNOPSIS
        Registers (or hides) a displayed property in the global object-property registry.

    .DESCRIPTION
        Adds a property descriptor to $Global:CLIPropertyRegistry, the declarative store
        consumed by Get-CLIObjectPropertyList to build the property list shown at the top
        of an object dialog view. The registry is a hashtable keyed by Type; each value is
        an ordered dictionary keyed by Name, so registration order is preserved and an
        entry with the same (Type, Name) is replaced in place (reload-safe, and lets a
        custom/client module override a base property by reusing its Name).

        A property is shown for an object when one of the object's resolved type tokens
        (see Resolve-CLIMenuType) matches Type, the requested view matches Function, and
        the optional Filter returns true.

        Ordering inside a view follows declaration order within each type-token tier
        (type-specific before generic), exactly like the menu registry. A client can place
        an added property relative to an existing one with -After/-Before (by Name), or
        fall back to a numeric -Order.

        Use -Hide to suppress a property (by Name) for the resolved types - typically a
        client hiding a base property it does not want.

    .PARAMETER Type
        The type token the property applies to (compact form, spaces removed), e.g.
        "ADUser", "ADComputer", "EPOSystem", or "*". Matched against Resolve-CLIMenuType.

    .PARAMETER Name
        Stable, unique-per-type identifier of the property (e.g.
        "ADUser.LogonInfo.PasswordExpired"). Registry key (replace on collision), anchor
        target for -After/-Before, and future i18n key. NOT the displayed label.

    .PARAMETER Header
        Displayed label of the property (the "N" of the rendered descriptor). Mandatory
        unless -Hide.

    .PARAMETER Expression
        Scriptblock producing the value ($_ is the object), i.e. the "E" of the rendered
        descriptor. Its referenced $_."attribute" drive the AD property enrichment, so an
        added property automatically loads the attribute it needs. Mandatory unless -Hide.

    .PARAMETER Function
        View(s) the property applies to. Accepts one or more values:
        "*" (default) = all views, "<name>" = that named view (compact form, spaces
        removed), "" = base view. Pass several to show it on several views.

    .PARAMETER Filter
        Optional scriptblock predicate evaluated against the object ($args[0]). The
        property is shown only when it returns truthy. A filter that throws hides the
        property (it never breaks the list).

    .PARAMETER After
        Place this property immediately after the property whose Name is given.

    .PARAMETER Before
        Place this property immediately before the property whose Name is given.

    .PARAMETER Order
        Numeric order fallback (default 100) used when no -After/-Before anchor applies.
        Ties fall back to declaration order.

    .PARAMETER HideIfEmpty
        Convenience: do not render the property when its value is empty (merged into
        Options as HideIfEmpty = $true).

    .PARAMETER Options
        Optional hashtable of extra rendering keys passed through verbatim to the
        descriptor (e.g. Pattern, ColorGroups, AllMatches, TextForegroundColor,
        MatchTextForegroundColor, AutoWidth). Keeps this function stable as new render
        options appear.

    .PARAMETER Hide
        Mark the property identified by Name as hidden for the resolved types. Header and
        Expression are not required in this mode.

    .PARAMETER Empty
        Register a marker that makes the view registry-driven while contributing no
        property. Use it for a content-only view (a table, no property block on top) so it
        shows no properties and does NOT inherit the type's base property block. Header and
        Expression are not required in this mode. Equivalent to the legacy convention of a
        Get-<Type>-<Func>_ObjectProperties function that returns $null.

    .EXAMPLE
        Register-CLIObjectProperty -Type ADUser -Name "ADUser.Department" `
            -Header "Department" -Expression { $_.department }

    .EXAMPLE
        # Client override: rename an EPO custom property and place it after the tags.
        Register-CLIObjectProperty -Type EPOSystem -Function CustomProperties `
            -Name "EPOSystem.CustomProperties.UserProperty1" -Header "Serial number" `
            -Expression { $_."EPOComputerProperties.UserProperty1" } -After "EPOSystem.CustomProperties.Tags"

    .EXAMPLE
        # Client hiding a base property it does not want.
        Register-CLIObjectProperty -Type ADUser -Name "ADUser.Company" -Hide

    .EXAMPLE
        # Content-only view: no property block on top, no base inheritance.
        Register-CLIObjectProperty -Type ADComputer -Function "InstalledPrograms" `
            -Name "ADComputer.InstalledPrograms.None" -Empty

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-06-17 - Loïc Ade
            - Initial release. Declarative property registry for the object dialog engine,
              companion of Register-CLIMenuButton. Registry keyed by Type then (ordered)
              by Name; same (Type, Name) replaces in place. Add/override/hide, per-view
              Function scoping, per-object Filter, anchor (-After/-Before) or numeric
              (-Order) placement, render passthrough via Options.
            - Added -Empty: a content-only view marker (registry-driven, no property,
              suppresses base inheritance), the registry form of a $null-returning
              legacy property function.
    #>
    [CmdletBinding(DefaultParameterSetName = "Define")]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Type,
        [Parameter(Mandatory, Position = 1)]
        [string]$Name,
        [Parameter(Mandatory, Position = 2, ParameterSetName = "Define")]
        [string]$Header,
        [Parameter(Mandatory, Position = 3, ParameterSetName = "Define")]
        [scriptblock]$Expression,
        [string[]]$Function = @('*'),
        [Parameter(ParameterSetName = "Define")]
        [scriptblock]$Filter,
        [Parameter(ParameterSetName = "Define")]
        [string]$After,
        [Parameter(ParameterSetName = "Define")]
        [string]$Before,
        [Parameter(ParameterSetName = "Define")]
        [int]$Order = 100,
        [Parameter(ParameterSetName = "Define")]
        [switch]$HideIfEmpty,
        [Parameter(ParameterSetName = "Define")]
        [hashtable]$Options,
        [Parameter(Mandatory, ParameterSetName = "Hide")]
        [switch]$Hide,
        [Parameter(Mandatory, ParameterSetName = "Empty")]
        [switch]$Empty
    )

    if ($Global:CLIPropertyRegistry -isnot [hashtable]) {
        $Global:CLIPropertyRegistry = @{}
    }

    $sType = $Type.Replace(' ', '')

    if ($Hide) {
        $oDescriptor = @{
            Type     = $sType
            Name     = $Name
            Function = $Function
            Hidden   = $true
        }
    } elseif ($Empty) {
        # Marker: makes the view registry-driven while contributing no property, so a
        # content-only view shows no property block (suppresses base inheritance).
        $oDescriptor = @{
            Type     = $sType
            Name     = $Name
            Function = $Function
            Empty    = $true
        }
    } else {
        # Render passthrough: only the supplied extras, plus the HideIfEmpty convenience.
        $hOptions = if ($Options) { $Options.Clone() } else { @{} }
        if ($HideIfEmpty) { $hOptions['HideIfEmpty'] = $true }

        $oDescriptor = @{
            Type       = $sType
            Name       = $Name
            Function   = $Function
            Header     = $Header
            Expression = $Expression
            Filter     = $Filter
            After      = if ($PSBoundParameters.ContainsKey('After'))  { $After }  else { $null }
            Before     = if ($PSBoundParameters.ContainsKey('Before')) { $Before } else { $null }
            Order      = $Order
            Options    = $hOptions
            Hidden     = $false
        }
    }

    if (-not $Global:CLIPropertyRegistry.ContainsKey($sType)) {
        $Global:CLIPropertyRegistry[$sType] = [ordered]@{}
    }
    # Same (Type, Name) replaces in place (ordered dictionary keeps the position).
    $Global:CLIPropertyRegistry[$sType][$Name] = $oDescriptor
}
