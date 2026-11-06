function Get-HostPortRegex {
    <#
    .SYNOPSIS
        Returns a regex pattern for matching host:port combinations

    .DESCRIPTION
        Generates a regex pattern that matches IPv4, IPv6 (in brackets), or DNS
        hostnames with an optional port number. Includes named capture groups
        Host, IPv4Host, IPv6Host, DNSHost, and Port.
        An IPv6 address without brackets is also accepted, but without port: in
        "::1:443" the ":443" is part of the address (RFC 3986 requires the brackets).

    .PARAMETER FullLine
        Anchor the pattern to match the entire line

    .OUTPUTS
        System.String. The regex pattern.

    .EXAMPLE
        "192.168.1.1:8080" -match (Get-HostPortRegex)

    .EXAMPLE
        if ("www.example.com:443" -match (Get-HostPortRegex -FullLine)) { $Matches.Host; $Matches.Port }

    .NOTES
        Author  : Loïc Ade
        Version : 1.1.0

        1.1.0 (2026-11-06)
            - A DNS name followed by a port ("www.example.com:443") never matched: the DNS
              pattern refused a ":" after the name (fixed in Get-DNSRegex 1.4.0)
            - IPv6 without brackets accepted (without port)
            - The port is not truncated any more: "srv:99999" no longer gives the port 9999
    #>
    Param(
        [switch]$FullLine
    )
    
    # Récupération des regex existantes
    $ipv4Regex = Get-IPRegex -IPv4
    $ipv6Regex = Get-IPRegex -IPv6
    $dnsRegex = Get-DNSRegex
    $portRegex = Get-PortRegex
    
    # Construction de la regex host avec support IPv6 entre crochets
    $ipv6WithBrackets = "\[(?<IPv6Host>" + $ipv6Regex.Replace('(?<ipv6>', '(?:')  + ")\]"
    $ipv4Host = "(?<IPv4Host>" + $ipv4Regex.Replace('(?<ipv4>', '(?:') + ")"
    $dnsHost = "(?<DNSHost>" + $dnsRegex.Replace('(?<dns>', '(?:') + ")"
    # IPv6 without brackets: last alternative, and never followed by a port
    $ipv6NoBrackets = "(?<IPv6Host>" + $ipv6Regex.Replace('(?<ipv6>', '(?:')  + ")(?!:)"

    $sRegex = "(?:(?<Host>$ipv6WithBrackets|$ipv4Host|$dnsHost)(?::(?<Port>$portRegex)(?![0-9]))?|(?<Host>$ipv6NoBrackets))"
    
    if ($FullLine) {
        return "^$sRegex$"
    } else {
        return $sRegex
    }
}