function Get-DNSRegex {
    <#
    .SYNOPSIS
        Returns a regex pattern for matching DNS hostnames

    .DESCRIPTION
        Generates a regex pattern for DNS names with named capture groups.
        Supports optional wildcard matching and full-line anchoring.
        Enforces RFC 1123 label rules: labels must start and end with a letter
        or digit, and may contain hyphens/underscores in between. Each label
        is limited to 63 characters. At least one label must contain a letter,
        which prevents purely numeric strings (e.g. "1.1.2") from matching.

    .PARAMETER FullLine
        Anchor the pattern to match the entire line

    .PARAMETER AllowWildcard
        Allow wildcard (*) as a standalone label in the DNS name

    .PARAMETER DontIncludeSubpatternName
        Omit named capture groups from the pattern

    .PARAMETER DontIncludeDnsPart
        Omit the dnspart capture group, keeping only the dns group

    .PARAMETER NoBoundary
        Omit the token boundaries, to embed the pattern in a larger one where the name is
        directly followed or preceded by other characters (e.g. "<name>_<date>").
        Without it, the name must be preceded by the start of the text, a separator
        (space , ; | brackets quotes < >), "@" or "/", and followed by the end of the text,
        a separator, "/", ":<port>" or a final dot (end of sentence).

    .OUTPUTS
        System.String. The regex pattern.

    .EXAMPLE
        "www.example.com" -match (Get-DNSRegex)

    .EXAMPLE
        "3com.example.com" -match (Get-DNSRegex)

    .EXAMPLE
        "1.1.2" -match (Get-DNSRegex)  # Returns False

    .NOTES
        Author  : Loïc Ade
        Version : 1.4.0

        1.4.0 (2026-11-06)
            - The letter lookahead only looks inside the name: it scanned up to the end of the
              text, so "1.1.2" was taken as a name when a letter came later ("1.1.2 host01")
            - Boundaries accept "server:443", "user@host", "https://host/path" and a final
              dot ("see example.com."): the name was not found in these strings, and
              Get-HostPortRegex never matched "host:port"
            - New NoBoundary switch to embed the pattern in a larger one
    #>
    Param(
        [switch]$FullLine,
        [switch]$AllowWildcard,
        [switch]$DontIncludeSubpatternName,
        [switch]$DontIncludeDnsPart,
        [switch]$NoBoundary
    )

    # Un label valide : commence et finit par une lettre ou un chiffre,
    # peut contenir des tirets/underscores au milieu, 63 caractères max
    $sEdgeChar  = "[\p{L}\p{Nd}]"
    $sInnerChar = "[\p{L}\p{Pc}\p{Pd}\p{Nd}]"
    $sBaseLabel = "(?:$sEdgeChar(?:$sInnerChar{0,61}$sEdgeChar)?)"
    $sBasePart  = if ($AllowWildcard) { "(?:\*|$sBaseLabel)" } else { $sBaseLabel }

    # Lookahead imposant qu'au moins une lettre soit présente dans le nom DNS
    # afin d'exclure les chaînes purement numériques comme "1.1.2".
    # Il ne parcourt que les caractères possibles d'un nom (chiffres, tirets, points, "*")
    # jusqu'à la première lettre : il ne déborde pas sur la suite du texte.
    $sLetterLookahead = "(?=[\p{Nd}\p{Pc}\p{Pd}.*]*\p{L})"

    # Délimiteurs naturels entourant un hostname (début et fin de token).
    # Début : séparateur, "@" (user@host) ou "/" (scheme://host).
    # Fin : séparateur, "/" (chemin), ":<port>" (mais pas le ":" d'une IPv6 comme "fe80::1")
    # ou un point final (fin de phrase).
    $sDelimiters    = "\s,;|\[\]()\{\}'`"<>"
    $sStartBoundary = "(?<![^$sDelimiters@/])"
    $sEndBoundary   = "(?=[$sDelimiters/]|$|\.(?![\p{L}\p{Nd}*])|:[0-9]+(?![\p{L}\p{Nd}:]))"
    if ($NoBoundary) {
        $sStartBoundary = ""
        $sEndBoundary = ""
    }

    $sResult = if ($DontIncludeSubpatternName) {
        "$sStartBoundary$sLetterLookahead$sBasePart(?:\.$sBasePart)*$sEndBoundary"
    } elseif ($DontIncludeDnsPart) {
        "$sStartBoundary$sLetterLookahead(?<dns>$sBasePart(?:\.$sBasePart)*)$sEndBoundary"
    } else {
        "$sStartBoundary$sLetterLookahead(?<dns>(?<dnspart>$sBasePart)(?:\.(?<dnspart>$sBasePart))*)$sEndBoundary"
    }

    if ($FullLine) {
        return "^$sResult$"
    } else {
        return $sResult
    }
}