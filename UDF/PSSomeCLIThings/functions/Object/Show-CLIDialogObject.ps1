function Show-CLIDialogObject {
    <#
    .SYNOPSIS
        Displays an interactive, convention-driven dialog for any object.

    .DESCRIPTION
        Entry point of the object dialog engine. Given an object (and optionally the
        name of a function/view to display), it:

            1. Runs any required connection step (Get-CLIDialogConnectFunction).
            2. Optionally transforms the object (Convert-<Type>To<Func>).
            3. Optionally enriches it up-front (Expand-<Type>[-<Func>]_Object).
            4. Resolves the action to run on selected values
               (Invoke-<Type>[-<Func>]_FunctionOnObject), defaulting to recursing
               into the value with this very function.
            5. Builds a paginated dialog (New-CLIDialogObjectBuilder) and runs the
               navigation loop (Invoke-CLIDialog), handling Back / Exit / Previous /
               Next / Refresh actions.

        Everything is resolved by naming convention, so the engine carries no
        project-specific knowledge: the hosting project simply defines functions that
        follow the contract below, and registers its default footer menu once via
        Set-CLIDialogDefaultMenu. This is the function projects call to display an
        object.

    .PARAMETER Object
        The object to display.

    .PARAMETER Function
        Optional friendly name of the function/view to display (e.g. "All Info").

    .PARAMETER ItemsPerPage
        Number of content rows per page. Defaults to 15.

    .OUTPUTS
        The terminating dialog action result (e.g. Exit/Back), or $null when the
        connection step is cancelled.

    .EXAMPLE
        Show-CLIDialogObject $user
        # Displays the default view of $user (uses Get-<Type>_DefaultProperty).

    .EXAMPLE
        Show-CLIDialogObject $computer "All Info"
        # Displays the "All Info" view of $computer.

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        Dependencies: Get-Function (PSSomeCoreThings)

        OBJECT DIALOG ENGINE - CONVENTION CONTRACT
        The engine resolves behaviour from functions the host project defines, named
        after the object's type and/or the requested function. In the patterns below
        <Type> is a PSTypeName with spaces removed, and <Func> is the requested
        function name with spaces removed. For each row the engine tries the listed
        candidates in order and uses the first one that exists; all are optional
        unless stated otherwise.

            Connect-<Type>To<Func>                        connection step, run first
            Connect-<Func> / Connect-<Func>_GUI             (fallbacks)
                -> may return a DialogResult.Action.Cancel to abort the display.

            Convert-<Type>To<Func>                        transform the object before
                                                          it is rendered.

            Expand-<Type>-<Func>_Object                   enrich the object up-front
            Expand-<Type>_Object                            (fallback)

            Get-<Type>_ObjectName                         display name for the header
                                                          (else .Name, else .ToString()).

            Get-<Type>-<Func>_ObjectProperties            property descriptors to show
            Get-<Func>_ObjectProperties                     (fallbacks)
            Get-<Type>_ObjectProperties

            Add-<Type>Properties [-Properties]            load/compute the requested
                                                          properties for sparse objects
                                                          (resolved over the whole type
                                                          hierarchy, first match wins).

            Get-<Type>-<Func>_ObjectContent               paginated content table
            Get-<Type>_ObjectContent                         (fallback)

            Get-<Func>_ProjectMenu                        per-object menu
            Get-<Type>-<Func>_ProjectMenu                   (fallbacks, with-function)
            Get-<Type>_ProjectMenu                           (no function)

            Get-<Type>_DefaultProperty                    default function name used
                                                          when -Function is omitted.

            Invoke-<Type>-<Func>_FunctionOnObject         action run on a selected
            Invoke-<Type>_FunctionOnObject                  value (fallback). When none
                                                          exists, selecting a value
                                                          recurses into Show-CLIDialogObject.

        In addition, the host project registers the default footer menu once with
        Set-CLIDialogDefaultMenu { ... } (e.g. Back / Search / Exit buttons), and may
        configure colors with Set-CLIDialogTheme.

        CHANGELOG:

        Version 1.0.0 - 2026-06-14 - Loïc Ade
            - Initial release. Extracted from the Hotline_tool script (formerly
              Show-Object_GUI) into PSSomeCLIThings; internal calls updated to
              Get-CLIDialogConnectFunction and New-CLIDialogObjectBuilder.
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$Object,
        [Parameter(Position = 1)]
        [string]$Function,
        [int]$ItemsPerPage = 15
    )
    $sFunction = $Function -replace " ", ""
    $f = Get-CLIDialogConnectFunction -Object $Object -Function $Function
    if ($f) {
        $oConnectResult = . $f
        if ($oConnectResult.PSTypeNames[0] -eq "DialogResult.Action.Cancel") {
            return $null
        }
    }
    $sType = $Object.PSTypeNames[0].Replace(" ", "")
    $sFunctionName = "Convert-$sType`To$sFunction"
    $f = Get-Function $sFunctionName
    $oObject = if ($f) {
        . $f $Object
    } else {
        $Object
    }
    $sFriendlyNameType = $oObject.PSTypeNames[0]
    $sType = $sFriendlyNameType.Replace(" ", "")
    $sFriendlyNameType = $sFriendlyNameType.Replace("_", " ")
    $f = Get-Function "Expand-$sType-$sFunction`_Object"
    if ($f) {
        . $f $oObject
    } else {
        $f = Get-Function "Expand-$sType`_Object"
        if ($f) {
            . $f $oObject
        }
    }
    $f = Get-Function "Invoke-$sType-$sFunction`_FunctionOnObject"
    $fFunctionOnValue = if ($f) {
        $f
    } else {
        $f = Get-Function "Invoke-$sType`_FunctionOnObject"
        if ($f) {
            $f
        } else {
            $sFunctionName = $MyInvocation.InvocationName.ToString()
            $oPSStack = Get-PSCallStack
            Get-Function $oPSStack[0].Command.ToString()
        }
    }
    $oDialogBuilder = if ($Function) {
        New-CLIDialogObjectBuilder -Object $oObject -Function $Function -ItemsPerPage $ItemsPerPage
    } else {
        New-CLIDialogObjectBuilder -Object $oObject -ItemsPerPage $ItemsPerPage
    }
    while ($true) {
        $oCurrentPageDialog = $oDialogBuilder.GetDialog()
        $oDialogResult = Invoke-CLIDialog $oCurrentPageDialog -Execute -FunctionToRunOnValue $fFunctionOnValue -Object $oObject
        if ($oDialogResult) {
            switch ($oDialogResult.PSTypeNames[0]) {
                "DialogResult.Action.Exit" {
                    return $oDialogResult
                }
                "DialogResult.Action.Back" {
                    if ($oDialogResult.Depth -eq 0) {
                        $oDialogResult.Depth += 1
                        return $oDialogResult
                    }
                }
                "DialogResult.Action.Previous" {
                    $oDialogBuilder.PreviousPage()
                }
                "DialogResult.Action.Next" {
                    $oDialogBuilder.NextPage()
                }
                "DialogResult.Action.Refresh" {
                    $bRefresh = if (($null -ne $oDialogResult.Value) -and ($oDialogResult.Value -is [scriptblock])) {
                        Invoke-Command $oDialogResult.Value -ArgumentList $oObject | Out-Null
                        $true
                    } elseif ("Refresh" -in $oObject.PSObject.Methods.Name) {
                        $oObject.Refresh()
                        $true
                    } else {
                        $false
                    }
                    if ($bRefresh) {
                        $oDialogBuilder.Refresh($oObject)
                    } else {
                        return $oDialogResult
                    }
                }
                default {
                    if ($oDialogResult.Value) {
                        $oDialogResult.Value | Out-Host
                    }
                    throw "Unmanaged action type"
                }
            }
        }
    }
}

# Backward-compatibility aliases for the object dialog engine.
# These map the former Hotline_tool names to the functions extracted into
# PSSomeCLIThings, so any call site missed during the rename keeps working.
# New code should call the canonical names directly.
Set-Alias -Name Show-Object_GUI         -Value Show-CLIDialogObject         -Scope Script
Set-Alias -Name New-ObjectDialogBuilder -Value New-CLIDialogObjectBuilder   -Scope Script
Set-Alias -Name Get-ObjectCustomDialog  -Value Get-CLIDialogObject          -Scope Script
Set-Alias -Name Get-ConnectFunction     -Value Get-CLIDialogConnectFunction -Scope Script
