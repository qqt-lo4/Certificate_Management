function Get-DNRegex {
    <#
    .SYNOPSIS
        Returns a regex pattern for matching X.500 Distinguished Names (DN)

    .DESCRIPTION
        Generates a regex pattern for certificate-style Distinguished Names.
        Supports common RDN attributes: CN, OU, O, L, ST, C, E, DC.
        Handles escaped commas, quoted values, and wildcard characters.

    .PARAMETER FullLine
        Anchor the pattern to match the entire line

    .PARAMETER DontIncludeSubpatternName
        Omit named capture groups from the pattern

    .OUTPUTS
        System.String. The regex pattern.

    .EXAMPLE
        "CN=server.example.com" -match (Get-DNRegex)

    .EXAMPLE
        "CN=*.example.com,O=MyOrg,C=FR" -match (Get-DNRegex -FullLine)

    .EXAMPLE
        'CN=server,OU=IT,O=Company,L=Paris,ST=IDF,C=FR' -match (Get-DNRegex)

    .NOTES
        Author  : Loïc Ade
        Version : 1.1.0

        1.1.0 (2026-11-06)
            - More attribute types: S (state, as Windows writes it), STREET, POSTALCODE,
              SERIALNUMBER, SN, G, GN, T, TITLE, UID, EMAIL, EMAILADDRESS, and the OID form
              ("2.5.4.3=x"): a subject copied from a Windows certificate ("S=IDF") was refused
        1.0.1 (2026-10-05)
            - Attribute types case-insensitive in the pattern itself ("cn=", "dc=" as LDAP writes
              them): it relied on -match ignoring case, and failed with -cmatch or [regex]::Match
        1.0.0 (2026-03-14)
            - Initial version
    #>
    Param(
        [switch]$FullLine,
        [switch]$DontIncludeSubpatternName
    )

    # RDN attribute types (case-insensitive: LDAP does not care, and neither must the caller's operator)
    # (longest names first: the alternation stops at the first one that fits)
    $sAttrType = "(?i:EMAILADDRESS|SERIALNUMBER|POSTALCODE|STREET|EMAIL|TITLE|UID|CN|OU|ST|SN|GN|DC|O|L|S|C|E|G|T|[0-9]+(?:\.[0-9]+)+)"

    # RDN value: quoted string or unquoted (with escaped commas allowed)
    $sAttrValue = '(?:"[^"]*"|(?:\\,|[^,])+)'

    # Single RDN: type=value
    $sRDN = "$sAttrType\s*=\s*$sAttrValue"

    # Full DN: one or more RDNs separated by commas
    $sResult = if ($DontIncludeSubpatternName) {
        "$sRDN(?:\s*,\s*$sRDN)*"
    } else {
        "(?<dn>$sRDN(?:\s*,\s*$sRDN)*)"
    }

    if ($FullLine) {
        return "^$sResult$"
    } else {
        return $sResult
    }
}
