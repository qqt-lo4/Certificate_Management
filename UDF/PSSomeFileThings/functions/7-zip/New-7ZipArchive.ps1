function New-7ZipArchive {
    <#
    .SYNOPSIS
        Creates a 7-Zip archive

    .DESCRIPTION
        Uses 7-Zip command line tool to create an archive (.7z or .zip) with a specified
        compression level, optionally protected by a password. Supports compression levels
        from 0 (no compression) to 9 (ultra compression).

        When -Password is supplied:
          - zip archives are encrypted with the method given by -ZipEncryptionMethod:
              * AES256 (default): strong, but AES-encrypted zip archives are NOT openable by
                the Windows Explorer built-in extractor (use 7-Zip / WinZip).
              * ZipCrypto: cryptographically weak, but openable natively by Windows Explorer
                and virtually every zip tool - prefer it only when compatibility matters more
                than security.
          - 7z archives are encrypted with AES-256 (the only method the format supports), and
            -EncryptFileNames additionally encrypts the archive headers (file names) via -mhe=on.

    .PARAMETER SevenZipExePath
        Path to 7za.exe executable (default: auto-detected via Get-7ZipPath).

    .PARAMETER Content
        Array of file or folder paths to include in the archive.

    .PARAMETER OutputArchivePath
        Path where the archive will be created.

    .PARAMETER ArchiveType
        Archive format: "7z" (default) or "zip".

    .PARAMETER CompressionLevel
        Compression level from 0 to 9 (default: 5).
        0 = No compression (copy mode)
        1 = Low compression (fastest)
        5 = Normal compression
        9 = Ultra compression

    .PARAMETER Password
        SecureString password protecting the archive.

    .PARAMETER ZipEncryptionMethod
        zip only. Encryption method when a password is set: "AES256" (default, secure) or
        "ZipCrypto" (weak but compatible with the Windows Explorer extractor). Ignored for 7z.

    .PARAMETER EncryptFileNames
        7z only. Also encrypt the archive headers (file names) via -mhe=on. Ignored for zip,
        whose format cannot encrypt file names.

    .OUTPUTS
        None. Creates the archive file.

    .EXAMPLE
        New-7ZipArchive -Content "C:\Folder1","C:\File.txt" -OutputArchivePath "C:\archive.7z"

    .EXAMPLE
        New-7ZipArchive -Content "C:\Data" -OutputArchivePath "C:\backup.7z" -CompressionLevel 9

    .EXAMPLE
        $pwd = Read-Host -AsSecureString -Prompt "Archive password"
        New-7ZipArchive -Content "C:\secret.key" -OutputArchivePath "C:\secret.zip" -ArchiveType zip -Password $pwd

    .EXAMPLE
        # Compatibility-first: openable by the Windows Explorer extractor.
        New-7ZipArchive -Content "C:\out" -OutputArchivePath "C:\out.zip" -ArchiveType zip -Password $pwd -ZipEncryptionMethod ZipCrypto

    .NOTES
        Author  : Loïc Ade
        Version : 1.1.0

        CHANGELOG:

        Version 1.1.0 - 2026-06-21 - Loïc Ade
            - Default -SevenZipExePath now resolved via Get-7ZipPath (fixes the removed
              Get-ScriptDir -FullPath default and handles the version-named tools subfolder)
            - Added -ArchiveType (7z|zip), -Password, -ZipEncryptionMethod (AES256|ZipCrypto)
              and -EncryptFileNames
            - 7-Zip is now started through System.Diagnostics.Process with arguments quoted per
              7-Zip's own parser rules, so passwords with special characters (spaces, $, \, ...)
              survive Windows PowerShell 5.1 native-argument quoting; throws on non-zero exit.
              A double-quote cannot be carried to 7-Zip and is rejected with a clear error.
            - Security note: 7-Zip only accepts the password on the command line, so it is
              briefly visible in the process command line while the archive is built

        Version 1.0.0 - Loïc Ade
            - Initial release
    #>
    Param(
        [string]$SevenZipExePath = (Get-7ZipPath),
        [Parameter(Mandatory)]
        [string[]]$Content,
        [Parameter(Mandatory)]
        [string]$OutputArchivePath,
        [ValidateSet("7z", "zip")]
        [string]$ArchiveType = "7z",

        #0 Don't compress at all.
        #This is called "copy mode."

        #1 Low compression.
        #This is called "fastest" mode.

        #9 Ultra compression
        [ValidateRange(0, 9)]
        [int]$CompressionLevel = 5,
        [securestring]$Password,
        [ValidateSet("AES256", "ZipCrypto")]
        [string]$ZipEncryptionMethod = "AES256",
        [switch]$EncryptFileNames
    )
    # Quote a single argument the way 7-Zip's own command-line parser expects, then build the
    # command line ourselves and start 7-Zip through System.Diagnostics.Process. Windows
    # PowerShell 5.1 mangles native-command arguments that contain double quotes, which would
    # corrupt a password such as a"b. 7-Zip's parser treats a double quote as a plain delimiter
    # that is always removed and offers NO way to embed a literal double quote in an argument,
    # so such an argument is rejected with a clear error rather than silently corrupted.
    # Backslashes are literal for 7-Zip (unlike the C runtime), so they are not doubled.
    function Get-7ZipQuotedArg {
        Param([string]$Argument)
        if ($Argument.Contains('"')) {
            throw "7-Zip cannot accept an argument containing a double-quote character: $Argument"
        }
        if ($Argument -match '[ \t]') { return '"' + $Argument + '"' }
        return $Argument
    }

    $aArgs = @(
        "a"
        "-mx$CompressionLevel"
        "-t$ArchiveType"
    )
    if ($Password) {
        if ($ArchiveType -eq "zip") {
            $aArgs += "-mem=$ZipEncryptionMethod"
        } elseif ($EncryptFileNames) {
            $aArgs += "-mhe=on"
        }
        $sPlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
        $aArgs += "-p$sPlainPassword"
    }
    $aArgs += $OutputArchivePath
    $aArgs += "--"
    $aArgs += $Content

    $sCommandLine = ($aArgs | ForEach-Object { Get-7ZipQuotedArg -Argument $_ }) -join " "
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $SevenZipExePath
    $psi.Arguments = $sCommandLine
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $oProcess = [System.Diagnostics.Process]::Start($psi)
    # Read both streams asynchronously to avoid a pipe-buffer deadlock.
    $oOutTask = $oProcess.StandardOutput.ReadToEndAsync()
    $oErrTask = $oProcess.StandardError.ReadToEndAsync()
    $oProcess.WaitForExit()
    $sStdOut = $oOutTask.Result
    $sStdErr = $oErrTask.Result
    if ($sStdOut) { Write-Verbose $sStdOut }
    if ($oProcess.ExitCode -ne 0) {
        throw "7-Zip failed (exit code $($oProcess.ExitCode)): $sStdErr$sStdOut"
    }
}