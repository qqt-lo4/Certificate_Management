function Get-MacAddressRegex {
    <#
    .SYNOPSIS
        Returns a regex pattern for matching MAC addresses

    .DESCRIPTION
        Generates a regex pattern that matches MAC addresses in various formats, with ONE
        separator throughout: by pairs ("aa:bb:cc:dd:ee:ff", "AA-BB-...", "aa.bb...", "aa bb ...",
        or none: "aabbccddeeff"), or by quartets ("aabb.ccdd.eeff" Cisco, "aabb-ccdd-eeff"
        HPE/Comware). Includes a named capture group "mac", and "symbols" capturing each of the
        six bytes (New-MACAddressObject rebuilds the address from it).

    .PARAMETER FullLine
        Anchor the pattern to match the entire line

    .OUTPUTS
        System.String. The regex pattern.

    .EXAMPLE
        "AA:BB:CC:DD:EE:FF" -match (Get-MacAddressRegex)

    .NOTES
        Author  : Loïc Ade
        Version : 1.2.0

        1.2.0 (2026-11-06)
            - The address is bounded: searched in a text, the pattern returned the first 12 hex
              digits of a longer value ("aabbccddeeff00")

        1.1.0 (2026-10-05)
            - One separator throughout: the previous pattern took any non-hex character, or
              none, between each pair, so "AA:BB-CCDD.EE FF" passed as a MAC address
            - Quartet forms ("aabb.ccdd.eeff", "aabb-ccdd-eeff") explicit
    #>
    Param(
        [switch]$FullLine
    )
    $x = "[A-Fa-f0-9]"
    $sByte = "(?<symbols>$x{2})"
    # By pairs: the separator of the first pair is required between all the others (or none at all)
    $sPairs = "$sByte(?<sep>[:\-. ]?)(?:$sByte\k<sep>){4}$sByte"
    # By quartets: Cisco "aabb.ccdd.eeff", HPE/Comware "aabb-ccdd-eeff"
    $sQuads = "$sByte$sByte(?<sep4>[.\-:])$sByte$sByte\k<sep4>$sByte$sByte"
    $sResult = "(?<![0-9A-Fa-f])(?<mac>$sPairs|$sQuads)(?![0-9A-Fa-f])"
    if ($FullLine) {
        return "^$sResult$"
    } else {
        return $sResult
    }
}
