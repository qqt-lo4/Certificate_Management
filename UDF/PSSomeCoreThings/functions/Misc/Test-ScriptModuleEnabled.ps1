function Test-ScriptModuleEnabled {
    <#
    .SYNOPSIS
        Tells whether a project/custom module is enabled in the script configuration.

    .DESCRIPTION
        Reads the "Modules" section of $Global:Config (a name -> bool map) and returns
        whether the named module should be loaded. The policy is opt-out: a module that
        is not listed is considered enabled. A module is disabled only when explicitly
        set to a falsy value (e.g. "SCCM": false).

        Used at startup to decide which Project_Modules / Custom_Modules to import.

    .PARAMETER Name
        The module name (matches the module folder name and the config key).

    .OUTPUTS
        [bool]. $true unless the module is explicitly disabled in $Global:Config.Modules.

    .EXAMPLE
        if (Test-ScriptModuleEnabled -Name "SCCM") { Import-Module ...\SCCM }

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-06-14 - Loïc Ade
            - Initial release. Opt-out module enablement check against
              $Global:Config.Modules.
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Name
    )
    $oModules = $Global:Config.Modules
    if ($oModules -and ($Name -in $oModules.Keys)) {
        return [bool]$oModules.$Name
    }
    return $true
}
