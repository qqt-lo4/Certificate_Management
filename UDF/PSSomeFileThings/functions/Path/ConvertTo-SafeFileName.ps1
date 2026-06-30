function ConvertTo-SafeFileName {
    <#
    .SYNOPSIS
        Turns an arbitrary string into a string usable as a Windows file or folder name

    .DESCRIPTION
        Replaces every character that is illegal in a Windows file/folder name so the result
        can be used to create a file or directory. The asterisk - common in wildcard names
        such as *.example.com - is mapped to the readable word "star" (giving star.example.com);
        every other illegal character (the rest of [System.IO.Path]::GetInvalidFileNameChars(),
        i.e. < > : " / \ | ? and the control characters) is replaced by -Replacement.

        Trailing dots and spaces (illegal at the end of a Windows name) are trimmed, reserved
        device names (CON, PRN, AUX, NUL, COM1-9, LPT1-9) are suffixed with an underscore, and
        an empty result falls back to -DefaultName.

        This is meant for the on-disk representation only: keep the original string for any
        place that is not a path.

    .PARAMETER Name
        The string to sanitize.

    .PARAMETER Replacement
        String substituted for each illegal character other than the asterisk. Default "_".

    .PARAMETER DefaultName
        Value returned when sanitizing leaves an empty/blank result (empty input, or input made
        only of illegal characters). Default "unnamed".

    .OUTPUTS
        [string]. A name safe to use as a file or folder name.

    .EXAMPLE
        ConvertTo-SafeFileName -Name "*.example.com"      # -> star.example.com

    .EXAMPLE
        ConvertTo-SafeFileName -Name 'a:b/c|d'            # -> a_b_c_d

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-06-21 - Loïc Ade
            - Initial release
            - Maps "*" to "star", other invalid file name characters to -Replacement
            - Trims trailing dots/spaces, guards reserved device names, empty -> -DefaultName
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [AllowEmptyString()]
        [string]$Name,
        [string]$Replacement = "_",
        [string]$DefaultName = "unnamed"
    )

    # Readable mapping for the wildcard asterisk first (so it does not become $Replacement).
    $sResult = $Name -replace '\*', 'star'

    # Replace every remaining character that is invalid in a Windows file name.
    foreach ($cInvalid in [System.IO.Path]::GetInvalidFileNameChars()) {
        if ($cInvalid -eq '*') { continue }   # already mapped to "star"
        $sResult = $sResult.Replace([string]$cInvalid, $Replacement)
    }

    # Trailing dots and spaces are not allowed at the end of a Windows name.
    $sResult = $sResult.TrimEnd('.', ' ')

    # Reserved device names (optionally followed by an extension) must not be used as-is.
    $sBase = $sResult.Split('.')[0]
    if ($sBase -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') {
        $sResult = $sResult + "_"
    }

    if ([string]::IsNullOrWhiteSpace($sResult)) { $sResult = $DefaultName }
    return $sResult
}
