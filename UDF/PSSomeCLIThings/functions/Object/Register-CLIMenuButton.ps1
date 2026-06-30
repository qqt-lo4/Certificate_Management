function Register-CLIMenuButton {
    <#
    .SYNOPSIS
        Registers a menu button descriptor in the global menu registry.

    .DESCRIPTION
        Adds a button to $Global:CLIMenuRegistry, the declarative registry consumed by
        New-CLIDialogMenuFromRegistry to build object dialog menus dynamically. The
        registry is a hashtable keyed by Type; each value is an ordered dictionary
        keyed by Name, so registration order is preserved and an entry with the same
        (Type, Name) is replaced in place (reload-safe, and lets a custom module
        override a base button by reusing its Name).

        A button is shown for an object when one of the object's resolved type tokens
        (see Resolve-CLIMenuType) matches Type, the requested view matches Function,
        and the optional Filter returns true.

        Row order follows declaration order (top to bottom) within each type-token
        tier; the MenuRow header alone identifies the row. There is no per-button
        newline option: the row (New-CLIDialogObjectsRow) handles line breaks.

    .PARAMETER Type
        The type token the button applies to (compact form, spaces removed), e.g.
        "ADComputer", "Computer", or "*" for a universal button. Matched against the
        tokens returned by Resolve-CLIMenuType.

    .PARAMETER MenuRow
        Header of the row the button belongs to (grouping key), e.g. "SCCM", "Display".

    .PARAMETER Name
        Stable, unique-per-type identifier of the button (e.g. "ADComputer.SCCM.RemoteControl").
        Used as the registry key (replace on collision) and as a future i18n key.

    .PARAMETER Text
        Displayed label, with "&" accelerator notation.

    .PARAMETER Object
        Scriptblock executed when the button is selected (receives the current object as $args[0]).

    .PARAMETER Function
        View(s) the button applies to. Accepts one or more values:
        "*" (default) = all views, "<name>" = that named view, "" = base view.
        Pass several to show the button on several views, e.g. -Function "","AllInfo".

    .PARAMETER Filter
        Optional scriptblock predicate evaluated against the current object ($args[0]).
        The button is shown only when it returns a truthy value. A filter that throws
        hides the button (it never breaks the menu).

    .PARAMETER Order
        Optional order of the button within its row. Default 100. Only useful to make
        a shared row (populated by several modules, e.g. "Find Endpoint in") ordered
        independently of module load order. Ties fall back to declaration order.

    .PARAMETER Keyboard
        Optional keyboard shortcut passed through to New-CLIDialogButton.

    .PARAMETER Underline
        Optional underline position passed through to New-CLIDialogButton.

    .EXAMPLE
        Register-CLIMenuButton -Type ADComputer -MenuRow "SCCM" -Name "ADComputer.SCCM.RemoteControl" `
            -Text "Run SCCM &Remote Control" -Object { Invoke-SCCMRemoteControl_GUI $args[0] }

    .EXAMPLE
        Register-CLIMenuButton -Type Computer -MenuRow "Find Endpoint in" -Name "Computer.FindIn.CheckPoint" `
            -Text "Check Poin&t EPM" -Filter { ($args[0].PSTypeNames -replace ' ','') -notcontains "CheckPointEPSOnPrem" } `
            -Object { Show-CLIDialogObject $args[0] "CheckPoint EPS OnPrem" }

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-06-14 - Loïc Ade
            - Initial release. Declarative menu button registry for the object dialog
              engine. Registry keyed by Type then (ordered) by Name; same (Type, Name)
              replaces in place. Row order = declaration order within each type tier.
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Type,
        [Parameter(Mandatory, Position = 1)]
        [string]$MenuRow,
        [Parameter(Mandatory, Position = 2)]
        [string]$Name,
        [Parameter(Mandatory, Position = 3)]
        [string]$Text,
        [Parameter(Mandatory, Position = 4)]
        [scriptblock]$Object,
        [string[]]$Function = @('*'),
        [scriptblock]$Filter,
        [int]$Order = 100,
        [string]$Keyboard,
        [int]$Underline
    )

    if ($Global:CLIMenuRegistry -isnot [hashtable]) {
        $Global:CLIMenuRegistry = @{}
    }

    $sType = $Type.Replace(' ', '')

    # Passthrough options for New-CLIDialogButton: only those explicitly supplied.
    $hButtonArgs = @{}
    if ($PSBoundParameters.ContainsKey('Keyboard'))  { $hButtonArgs['Keyboard']  = $Keyboard }
    if ($PSBoundParameters.ContainsKey('Underline')) { $hButtonArgs['Underline'] = $Underline }

    $oDescriptor = @{
        Type       = $sType
        Function   = $Function
        MenuRow    = $MenuRow
        Name       = $Name
        Text       = $Text
        Object     = $Object
        Filter     = $Filter
        Order      = $Order
        ButtonArgs = $hButtonArgs
    }

    if (-not $Global:CLIMenuRegistry.ContainsKey($sType)) {
        $Global:CLIMenuRegistry[$sType] = [ordered]@{}
    }
    # Same (Type, Name) replaces in place (ordered dictionary keeps the position).
    $Global:CLIMenuRegistry[$sType][$Name] = $oDescriptor
}
