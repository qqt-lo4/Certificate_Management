function Get-CLIDialogConnectFunction {
    <#
    .SYNOPSIS
        Resolves the connection function to run before displaying an object.

    .DESCRIPTION
        Part of the convention-driven object dialog engine. Looks up, by naming
        convention, the function that establishes any connection required before an
        object (or one of its functions) can be displayed. Resolution order:

            1. Connect-<Type>To<Function>   (for each type in the object hierarchy)
            2. Connect-<Function>
            3. Connect-<Function>_GUI

        where <Type> is each PSTypeName of the object (spaces removed) and <Function>
        is the requested function name (spaces removed). Returns the first matching
        command, or $null when none is found.

    .PARAMETER Object
        The object about to be displayed. Its PSTypeNames drive the type-specific
        lookup.

    .PARAMETER Function
        The friendly name of the requested function/view (e.g. "All Info"). Spaces
        are removed before building the candidate function names.

    .OUTPUTS
        [System.Management.Automation.CommandInfo] or $null.

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        Dependencies: Get-Function (PSSomeCoreThings)

        CHANGELOG:

        Version 1.0.0 - 2026-06-14 - Loïc Ade
            - Initial release. Extracted from the Hotline_tool script (formerly
              Get-ConnectFunction) into PSSomeCLIThings.
            - Resolve the function suffix from the passed -Function parameter
              instead of relying on a $sFunction variable inherited from the
              caller's scope (dynamic scoping). The function is now self-contained.
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$Object,
        [Parameter(Position = 1)]
        [string]$Function
    )
    $sFunction = $Function -replace " ", ""
    $fResult = $null
    $i = 0
    while (($null -eq $fResult) -and ($i -lt $Object.PSObject.TypeNames.Count)) {
        $f = Get-Function "Connect-$($Object.PSTypeNames[$i] -replace ' ', '')To$sFunction"
        if ($f) {
            $fResult = $f
        }
        $i++
    }
    if ($fResult) {
        return $fResult
    } else {
        $f = Get-Function "Connect-$sFunction"
        if ($f) {
            return $f
        } else {
            $f = Get-Function "Connect-$sFunction`_GUI"
            if ($f) {
                return $f
            } else {
                return $null
            }
        }
    }
}
