function Get-7ZipPath {
    <#
    .SYNOPSIS
        Resolves the architecture-appropriate 7za.exe shipped under the tools directory

    .DESCRIPTION
        Locates the 7-Zip standalone console executable (7za.exe) embedded in the
        application tools folder. 7-Zip is typically shipped inside a version-named folder
        (e.g. tools\7-Zip\7z2601-extra), and the "extra" package contains several
        architecture builds:

            <version>\7za.exe        x86 (runs everywhere through WOW64 / emulation)
            <version>\x64\7za.exe    x64
            <version>\arm64\7za.exe  ARM64

        Resolution is tolerant of layout:
          - When tools\7-Zip contains a single subfolder, it is used as the version folder
            (via Get-ScriptDir -ResolveSingleSubFolder).
          - Otherwise the tools\7-Zip folder itself is used (e.g. 7za.exe placed directly
            there, or several versions side by side).
          - The build matching the OS architecture is preferred (x64 or arm64), falling
            back to the x86 binary, and finally to a recursive search for any 7za.exe.

        OS architecture is read from PROCESSOR_ARCHITEW6432 first (set when a 32-bit
        process runs on a 64-bit OS), then PROCESSOR_ARCHITECTURE, so the x64 build is
        preferred even from a 32-bit PowerShell host.

        The auto-resolved path is cached in a global variable so repeated calls (this
        function is meant to be reused in several places) skip the file system lookups. The
        cache is revalidated with Test-Path on each call and is bypassed when -SevenZipRoot
        is supplied or -Refresh is used.

    .PARAMETER SevenZipRoot
        Explicit path to the folder containing the 7za.exe build(s). When omitted, the
        folder is resolved automatically under tools\7-Zip. Supplying this parameter
        bypasses (and does not populate) the cache.

    .PARAMETER Refresh
        Ignore any cached value and resolve 7za.exe again, updating the cache.

    .OUTPUTS
        [string]. Full path to the resolved 7za.exe.

    .EXAMPLE
        $7z = Get-7ZipPath
        & $7z a -tzip archive.zip C:\data

    .EXAMPLE
        # Point at a specific version folder instead of auto-resolving it:
        Get-7ZipPath -SevenZipRoot "C:\Tools\7-Zip\7z2601-extra"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-06-21 - Loïc Ade
            - Initial release
            - Resolves the version-named 7-Zip folder, tolerating layouts with zero or
              several subfolders by falling back to the tools\7-Zip folder
            - Selects the x64 / arm64 build matching the OS architecture, falling back to
              the x86 binary and then to a recursive search for any 7za.exe
            - Caches the auto-resolved path in $Global:PSSomeFileThings_7ZipPath (revalidated
              with Test-Path, bypassed by -SevenZipRoot, refreshable with -Refresh)
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [string]$SevenZipRoot,
        [switch]$Refresh
    )

    # Return the cached result when resolving automatically (revalidated against the disk).
    if (-not $SevenZipRoot -and -not $Refresh -and
        $Global:PSSomeFileThings_7ZipPath -and
        (Test-Path -LiteralPath $Global:PSSomeFileThings_7ZipPath -PathType Leaf)) {
        return $Global:PSSomeFileThings_7ZipPath
    }

    $sBase = if ($SevenZipRoot) {
        $SevenZipRoot
    } else {
        try {
            Get-ScriptDir -ToolsDir -ToolName "7-Zip" -ResolveSingleSubFolder
        } catch {
            # zero or several version subfolders -> use the 7-Zip folder directly
            Get-ScriptDir -ToolsDir -ToolName "7-Zip"
        }
    }

    $sOsArch = if ($env:PROCESSOR_ARCHITEW6432) { $env:PROCESSOR_ARCHITEW6432 } else { $env:PROCESSOR_ARCHITECTURE }
    $sArchSub = switch ($sOsArch) {
        "AMD64" { "x64" }
        "ARM64" { "arm64" }
        default { $null }   # x86 -> root 7za.exe
    }

    $sResult = $null

    # Fast path: the expected locations under the resolved base.
    $aPreferred = @()
    if ($sArchSub) { $aPreferred += (Join-Path $sBase "$sArchSub\7za.exe") }
    $aPreferred += (Join-Path $sBase "7za.exe")   # x86 build / universal fallback
    foreach ($sCandidate in $aPreferred) {
        if (Test-Path -LiteralPath $sCandidate -PathType Leaf) {
            $sResult = $sCandidate
            break
        }
    }

    # Fallback: search recursively (covers several versions side by side or unusual layouts).
    if (-not $sResult) {
        $aFound = @(Get-ChildItem -LiteralPath $sBase -Filter "7za.exe" -File -Recurse -ErrorAction SilentlyContinue)
        if ($aFound.Count -gt 0) {
            $oArch = if ($sArchSub) { $aFound | Where-Object { $_.Directory.Name -eq $sArchSub } | Select-Object -First 1 } else { $null }
            $sResult = if ($oArch) {
                $oArch.FullName
            } else {
                (@($aFound | Sort-Object @{ Expression = { ($_.FullName -split '[\\/]').Count } }, FullName)[0]).FullName
            }
        }
    }

    if (-not $sResult) {
        throw "7za.exe not found under '$sBase'."
    }

    # Cache only the auto-resolved result (an explicit -SevenZipRoot is caller-specific).
    if (-not $SevenZipRoot) {
        $Global:PSSomeFileThings_7ZipPath = $sResult
    }
    return $sResult
}
