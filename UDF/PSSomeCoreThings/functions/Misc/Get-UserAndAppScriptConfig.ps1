function Get-UserAndAppScriptConfig {
    <#
    .SYNOPSIS
        Loads and merges user, domain, and application configurations

    .DESCRIPTION
        Loads up to three JSON config files (app, domain, user) and merges them into a
        single hashtable. User overrides app, and domain overrides the result
        (merge order: (user <- app) <- domain), so domain-level settings win.

        Each file is looked up independently in a configurable location, given by the
        matching -<Scope>ConfigLocation parameter. Supported locations mirror
        Get-ScriptDir (InputDir, OutputDir, WorkingDir) plus ScriptRoot, AppData and
        ProgramData. ScriptRoot/InputDir/AppData/ProgramData go through Get-ScriptConfig
        (which keeps the input/<ProjectName> sub-folder probing); OutputDir/WorkingDir
        are resolved through Get-ScriptDir and loaded from that explicit folder.

    .PARAMETER AppConfigFileName
        Application config filename (default: "config.json").

    .PARAMETER UserConfigFileName
        User config filename (default: auto-generated from domain and username).

    .PARAMETER DomainConfigFileName
        Domain config filename (default: auto-generated from domain).

    .PARAMETER AppConfigLocation
        Location to load the application config from (default: InputDir).

    .PARAMETER UserConfigLocation
        Location to load the user config from (default: InputDir).

    .PARAMETER DomainConfigLocation
        Location to load the domain config from (default: InputDir).

    .OUTPUTS
        [Hashtable]. Merged configuration from all sources, or $null if none found.

    .EXAMPLE
        $config = Get-UserAndAppScriptConfig
        # Loads app/user/domain configs from the input directory and merges them.

    .EXAMPLE
        $config = Get-UserAndAppScriptConfig -DomainConfigLocation ProgramData
        # Loads the domain config from ProgramData, the others from the input directory.

    .NOTES
        Author  : Loïc Ade
        Version : 2.0.0

        Dependencies: Merge-Hashtable (PSSomeDataThings)

        CHANGELOG:

        Version 2.0.0 - 2026-06-14 - Loïc Ade
            - Replaced the per-config location switches (AppConfigScriptRoot,
              UserConfigAppData, ...) with three -<Scope>ConfigLocation parameters
              (App/User/Domain), each accepting a Get-ScriptDir-style location plus
              AppData/ProgramData. Default is InputDir.
            - Removed the obsolete DevConfigFolderName parameter (ignored downstream
              since Get-ScriptConfig moved to Get-RootScriptConfigFile).
            - Fixed config merge dropping user values, then moved the merge out to the
              shared Merge-Hashtable (PSSomeDataThings) instead of an embedded copy.
              That shared function now deep-merges any IDictionary (including the
              OrderedDictionary returned by ConvertTo-Hashtable).

        Version 1.0.0 - Loïc Ade
            - Initial release.
    #>

    Param(
        [string]$AppConfigFileName = "config.json",
        [string]$UserConfigFileName = "user_$($env:USERDNSDOMAIN)_$($env:USERNAME).json",
        [string]$DomainConfigFileName = "domain_$($env:USERDNSDOMAIN).json",
        [ValidateSet('ScriptRoot', 'InputDir', 'OutputDir', 'WorkingDir', 'AppData', 'ProgramData')]
        [string]$AppConfigLocation = 'InputDir',
        [ValidateSet('ScriptRoot', 'InputDir', 'OutputDir', 'WorkingDir', 'AppData', 'ProgramData')]
        [string]$UserConfigLocation = 'InputDir',
        [ValidateSet('ScriptRoot', 'InputDir', 'OutputDir', 'WorkingDir', 'AppData', 'ProgramData')]
        [string]$DomainConfigLocation = 'InputDir'
    )
    Begin {
        function Get-ConfigByLocation {
            Param(
                [Parameter(Mandatory, Position = 0)]
                [string]$FileName,
                [Parameter(Mandatory, Position = 1)]
                [string]$Location
            )
            switch ($Location) {
                'ScriptRoot'  { return Get-ScriptConfig -ConfigFileName $FileName -ToHashtable -ScriptRoot }
                'InputDir'    { return Get-ScriptConfig -ConfigFileName $FileName -ToHashtable -InputDir }
                'AppData'     { return Get-ScriptConfig -ConfigFileName $FileName -ToHashtable -AppData }
                'ProgramData' { return Get-ScriptConfig -ConfigFileName $FileName -ToHashtable -ProgramData }
                default {
                    # OutputDir / WorkingDir: Get-ScriptConfig has no switch for these,
                    # and its -ConfigFilePath route depends on Resolve-PathWithVariables
                    # (another module). Resolve through Get-ScriptDir and load directly.
                    $hScriptDir = @{ $Location = $true }
                    $sPath = Join-Path (Get-ScriptDir @hScriptDir) $FileName
                    if (Test-Path -Path $sPath -PathType Leaf) {
                        return (Get-Content -Path $sPath | ConvertFrom-Json | ConvertTo-Hashtable)
                    }
                    return $null
                }
            }
        }

        $hUserConfig   = Get-ConfigByLocation -FileName $UserConfigFileName   -Location $UserConfigLocation
        $hDomainConfig = Get-ConfigByLocation -FileName $DomainConfigFileName -Location $DomainConfigLocation
        $hAppConfig    = Get-ConfigByLocation -FileName $AppConfigFileName    -Location $AppConfigLocation
    }
    Process {

    }
    End {
        $hResult = Merge-Hashtable (Merge-Hashtable $hUserConfig $hAppConfig) $hDomainConfig
        return $hResult
    }
}
