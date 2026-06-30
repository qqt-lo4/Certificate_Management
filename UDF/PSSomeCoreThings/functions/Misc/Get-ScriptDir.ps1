function Get-ScriptDir {
    <#
    .SYNOPSIS
        Gets application directories (input, output, working, or tools)

    .DESCRIPTION
        Returns the path to a standard application subfolder relative to the root script.
        Supports dev folder structure detection for organized project layouts.

    .PARAMETER InputDir
        Return the input directory path.

    .PARAMETER OutputDir
        Return the output directory path.

    .PARAMETER WorkingDir
        Return the working directory path.

    .PARAMETER ToolsDir
        Return the tools directory path (requires ToolName).

    .PARAMETER ToolName
        Name of the tool subfolder under tools.

    .PARAMETER ResolveSingleSubFolder
        Tools mode only. Descend into the unique subfolder found directly under the tool
        directory and return that subfolder instead. Useful when a tool is shipped inside a
        version-named folder (e.g. tools\7-Zip\7z2601-extra) so the version stays in the
        folder name and the caller does not have to know it. Throws when the tool directory
        does not contain exactly one subfolder. Can be combined with -FindFile, in which case
        the file is searched after the subfolder has been resolved.

    .PARAMETER FindFile
        Tools mode only. Search recursively under the tool directory (after
        -ResolveSingleSubFolder has been applied, when present) for the named file and return
        its full path instead of the directory. When several copies exist, the shallowest
        match is returned, then alphabetical order, so the result is deterministic. Throws
        when the file cannot be found. Not suitable when the relevant copy depends on
        architecture (e.g. 7-Zip ships x86/x64/arm64 binaries) - use -ResolveSingleSubFolder
        with a dedicated resolver in that case.

    .PARAMETER CustomModules
        Return the custom (client-specific) modules directory path, named
        "Custom_Modules" under the root script directory. Can be redirected by a
        root script argument (e.g. to point at a client's shared modules folder),
        and is not nested under the project name when a .devfolder marker is present.

    .OUTPUTS
        [String]. Directory path.

    .EXAMPLE
        $inputDir = Get-ScriptDir -InputDir

    .EXAMPLE
        $toolsDir = Get-ScriptDir -ToolsDir -ToolName "7zip"

    .EXAMPLE
        $customModulesDir = Get-ScriptDir -CustomModules

    .NOTES
        Author  : Loïc Ade
        Version : 1.6.0

        1.0.0 - First version

        1.1.0 (2026-03-05)
            - Corrected bugs of Get-RootScriptPath
            - Removes -FullPath parameter (always returns full path)

        1.2.0 (2026-03-08)
            - InputDir, OutputDir and WorkingDir can be overridden by root script parameters
            - ParameterSetNames renamed to match parameter names
            - Folder name derived from ParameterSetName

        1.3.0 (2026-03-10)
            - Uses Get-RootScriptInfo instead of Get-RootScriptPath, Get-RootScriptName and Get-RootScriptArguments

        1.4.0 (2026-04-23)
            - Emits a Write-Warning when a redirected directory argument is provided but does not exist,
              instead of silently falling back to the default path

        1.5.0 (2026-06-14)
            - Added -CustomModules parameter set returning the "Custom_Modules" folder
              (client-specific modules), redirectable by a root script argument and not
              nested under the project name under .devfolder

        1.6.0 (2026-06-21)
            - Tools mode: added -ResolveSingleSubFolder (descend into the unique versioned
              subfolder) and -FindFile (recursive, deterministic lookup of a named file,
              shallowest match first). Both are optional and composable.

    #>

    Param(
        [Parameter(ParameterSetName = "InputDir", Mandatory)]
        [switch]$InputDir,
        [Parameter(ParameterSetName = "OutputDir", Mandatory)]
        [switch]$OutputDir,
        [Parameter(ParameterSetName = "WorkingDir", Mandatory)]
        [switch]$WorkingDir,
        [Parameter(ParameterSetName = "ToolsDir", Mandatory)]
        [switch]$ToolsDir,
        [Parameter(ParameterSetName = "ToolsDir", Mandatory)]
        [string]$ToolName,
        [Parameter(ParameterSetName = "ToolsDir")]
        [switch]$ResolveSingleSubFolder,
        [Parameter(ParameterSetName = "ToolsDir")]
        [string]$FindFile,
        [Parameter(ParameterSetName = "CustomModules", Mandatory)]
        [switch]$CustomModules
    )
    Begin {
        $rootInfo = Get-RootScriptInfo
    }
    Process {
        if ($InputDir -or $OutputDir -or $WorkingDir -or $CustomModules) {
            $sRootArgValue = $rootInfo.Arguments[$PSCmdlet.ParameterSetName]
            if (-not [string]::IsNullOrEmpty($sRootArgValue)) {
                if (Test-Path $sRootArgValue -PathType Container) {
                    return $sRootArgValue
                }
                Write-Warning "Redirected $($PSCmdlet.ParameterSetName) path does not exist: '$sRootArgValue'. Falling back to default."
            }
        }

        $sFolderName = if ($PSCmdlet.ParameterSetName -eq "CustomModules") {
            # Fixed name (not derived): the custom client modules folder.
            "Custom_Modules"
        } else {
            $sTmp = $PSCmdlet.ParameterSetName -replace 'Dir$', ''
            $sTmp.Substring(0, 1).ToLower() + $sTmp.Substring(1)
        }
        $sResult = $rootInfo.Directory + "\" + $sFolderName
        if ($PSCmdlet.ParameterSetName -eq "ToolsDir") {
            $sResult += "\" + $ToolName
        }
        if (Test-Path ($rootInfo.Directory + "\.devfolder")) {
            $sResult = switch ($PSCmdlet.ParameterSetName) {
                # Tools and custom modules are not nested under the project name.
                "ToolsDir" { $sResult }
                "CustomModules" { $sResult }
                default { $sResult + "\" + $rootInfo.Name }
            }
        }
        if ($PSCmdlet.ParameterSetName -eq "ToolsDir") {
            if ($ResolveSingleSubFolder) {
                $aSubFolders = @(Get-ChildItem -LiteralPath $sResult -Directory -ErrorAction Stop)
                if ($aSubFolders.Count -ne 1) {
                    throw "Get-ScriptDir -ResolveSingleSubFolder expected exactly one subfolder under '$sResult' but found $($aSubFolders.Count)."
                }
                $sResult = $aSubFolders[0].FullName
            }
            if ($FindFile) {
                $oFound = Get-ChildItem -LiteralPath $sResult -Filter $FindFile -File -Recurse -ErrorAction SilentlyContinue |
                    Sort-Object @{ Expression = { ($_.FullName -split '[\\/]').Count } }, FullName |
                    Select-Object -First 1
                if (-not $oFound) {
                    throw "Get-ScriptDir -FindFile could not find '$FindFile' under '$sResult'."
                }
                return $oFound.FullName
            }
        }
        return $sResult
    }
    End {}
}