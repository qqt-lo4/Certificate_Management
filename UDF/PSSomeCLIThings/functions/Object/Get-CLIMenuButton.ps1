function Get-CLIMenuButton {
    <#
    .SYNOPSIS
        Returns registered menu button descriptors (inspection / debugging).

    .DESCRIPTION
        Enumerates $Global:CLIMenuRegistry and returns the stored button descriptors,
        optionally filtered by Type and/or Name. Useful to inspect what a module has
        registered, to detect overrides, or while debugging menu composition.

    .PARAMETER Type
        Optional type token to filter on (spaces removed, case-insensitive).

    .PARAMETER Name
        Optional button Name to filter on (case-insensitive).

    .OUTPUTS
        Array of button descriptor hashtables (possibly empty).

    .EXAMPLE
        Get-CLIMenuButton -Type ADComputer

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-06-14 - Loïc Ade
            - Initial release.
    #>
    Param(
        [string]$Type,
        [string]$Name
    )

    if ($Global:CLIMenuRegistry -isnot [hashtable]) {
        return @()
    }

    $sType = if ($PSBoundParameters.ContainsKey('Type')) { $Type.Replace(' ', '') } else { $null }

    $aResult = New-Object System.Collections.Generic.List[object]
    foreach ($sRegType in $Global:CLIMenuRegistry.Keys) {
        if ($sType -and ($sRegType -ne $sType)) { continue }
        foreach ($sRegName in $Global:CLIMenuRegistry[$sRegType].Keys) {
            if ($Name -and ($sRegName -ne $Name)) { continue }
            $aResult.Add($Global:CLIMenuRegistry[$sRegType][$sRegName])
        }
    }
    return , $aResult.ToArray()
}
