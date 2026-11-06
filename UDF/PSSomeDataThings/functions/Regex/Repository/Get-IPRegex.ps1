function Get-IPRegex {
    <#
    .SYNOPSIS
        Returns a regex pattern for matching IP addresses

    .DESCRIPTION
        Generates regex patterns for IPv4, IPv6, or both. Patterns include
        named capture groups (ipv4, ipv6). Optionally anchored to full line.

    .PARAMETER IPv4
        Return only IPv4 pattern

    .PARAMETER IPv6
        Return only IPv6 pattern

    .PARAMETER FullLine
        Anchor the pattern to match the entire line

    .OUTPUTS
        System.String. The regex pattern.

    .EXAMPLE
        "192.168.1.1" -match (Get-IPRegex -IPv4)

    .NOTES
        Author  : Loïc Ade
        Version : 1.4.0

        1.4.0 (2026-11-06)
            - Addresses are bounded: searched in a text (without FullLine), the pattern returned a
              piece of a longer value ("1.2.3.25" in "1.2.3.256", "11.2.3.4" in "311.2.3.4",
              "1.2.3.4" in "1.2.3.4.5", "::ffff:1" in "::ffff:1.2.3.4"). FullLine verdicts unchanged

        1.3.0 (2026-10-05)
            - IPv6 rebuilt from the RFC 3986 grammar (IPv6address, rule by rule): the previous
              pattern refused "::" and every compressed form whose embedded IPv4 follows groups
              placed after "::" (e.g. "1:2:3:4::5:1.2.3.4", "2001:db8::ef01:10.20.30.40").
              Checked against node:net on 88 addresses: identical verdicts (PS 5.1 and 7)
    #>
    Param(
        [switch]$IPv4,
        [switch]$IPv6,
        [switch]$FullLine,
        [switch]$DontIncludeSubpatternName
    )

    # Bounds (not preceded / followed by a digit or ".<digit>") so that a search in a text never
    # returns a piece of a longer value
    $sBaseIPv4Regex = "(?<![0-9]\.?)(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9][0-9]|[0-9])(?!\.?[0-9])"
    # IPv6address of RFC 3986 (section 3.2.2), one alternative per rule:
    #   h16 = 1 to 4 hex digits; ls32 = "h16:h16" or an IPv4 address (the last 32 bits)
    $h = '[0-9A-Fa-f]{1,4}'
    $sLs32 = "(?:$h`:$h|$sBaseIPv4Regex)"
    $sBaseIPv6Regex = '(?:' + (@(
        "(?:$h`:){6}$sLs32",                          #                    6( h16 ":" ) ls32
        "::(?:$h`:){5}$sLs32",                        #               "::" 5( h16 ":" ) ls32
        "(?:$h)?::(?:$h`:){4}$sLs32",                 # [ h16 ]       "::" 4( h16 ":" ) ls32
        "(?:(?:$h`:){0,1}$h)?::(?:$h`:){3}$sLs32",    # [ *1(h16 ":") h16 ] "::" 3( h16 ":" ) ls32
        "(?:(?:$h`:){0,2}$h)?::(?:$h`:){2}$sLs32",    # [ *2(h16 ":") h16 ] "::" 2( h16 ":" ) ls32
        "(?:(?:$h`:){0,3}$h)?::$h`:$sLs32",           # [ *3(h16 ":") h16 ] "::" h16 ":" ls32
        "(?:(?:$h`:){0,4}$h)?::$sLs32",               # [ *4(h16 ":") h16 ] "::" ls32
        "(?:(?:$h`:){0,5}$h)?::$h",                   # [ *5(h16 ":") h16 ] "::" h16
        "(?:(?:$h`:){0,6}$h)?::"                      # [ *6(h16 ":") h16 ] "::"
    ) -join '|') + ')'
    $sBaseIPv6Regex = "(?<![0-9A-Fa-f:])$sBaseIPv6Regex(?![0-9A-Fa-f:]|\.[0-9])"

    $sIPv4Regex = if ($DontIncludeSubpatternName) {
        $sBaseIPv4Regex
    } else {
        "(?<ipv4>$sBaseIPv4Regex)"
    }
    $sIPv6Regex = if ($DontIncludeSubpatternName) {
        $sBaseIPv6Regex
    } else {
        "(?<ipv6>$sBaseIPv6Regex)"
    }

    $b4 = $IPv4 -or ((-not $IPv4) -and (-not $IPv6))
    $b6 = $IPv6 -or ((-not $IPv4) -and (-not $IPv6))
    if ($FullLine) {
        $sIPv4Regex = "^$sIPv4Regex$"
        $sIPv6Regex = "^$sIPv6Regex$"
    } 
    $sResult = if ($b4 -and $b6) {
        $sIPv4Regex + "|" + $sIPv6Regex
    } elseif ($b4 -and -not $b6) {
        $sIPv4Regex
    } elseif (-not $b4 -and $b6) {
        $sIPv6Regex
    } else {
        throw [System.ArgumentException] "Impossible state"
    }
    return $sResult
}