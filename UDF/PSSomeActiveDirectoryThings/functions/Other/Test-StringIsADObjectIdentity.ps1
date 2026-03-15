function Test-StringIsADObjectIdentity {
    <#
    .SYNOPSIS
        Tests whether a string matches a recognized AD object identity format

    .DESCRIPTION
        Parses a string against multiple AD identity patterns: DOMAIN\user (principal name),
        user@domain (UPN), distinguished name, GUID, SID, or plain name. Returns an ordered
        hashtable with the identity value, type, and optional server, or $null if no match.

    .PARAMETER InputString
        The string to test as an AD object identity.

    .PARAMETER DomainRegex
        Regex pattern for matching domain names.

    .PARAMETER UsernameRegex
        Regex pattern for matching usernames.

    .PARAMETER DNRegex
        Regex pattern for matching distinguished names.

    .PARAMETER GUIDRegex
        Regex pattern for matching GUIDs.

    .PARAMETER SIDRegex
        Regex pattern for matching SIDs.

    .OUTPUTS
        [ordered hashtable] or $null. Contains Identity, Category, Type, optionally Server, and Details.

    .EXAMPLE
        Test-StringIsADObjectIdentity -InputString "user@domain.com"
        # Returns @{ Identity = "user"; Category = "ADObjectIdentity"; Type = "upn"; Server = "domain.com"; ... }

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$InputString,
        [string]$DomainRegex = "(?<domain>[A-Za-z._0-9-]+)",
        [string]$UsernameRegex = "(?<user>[\p{L}\p{Pc}\p{Pd}\p{Nd} *]+)",
        [string]$DNRegex = "(?<dn>.+,((dc|DC)=[^,]+))",
        [string]$GUIDRegex = "(?<guid>[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12})",
        [string]$SIDRegex = "(?<sid>S-1-[0-59]-\d{2}-\d{8,10}-\d{8,10}-\d{8,10}-[1-9]\d{3})"
    )
    $sPattern = "^(?<principalname>$DomainRegex\\$UsernameRegex)`$|^(?<upn>$UsernameRegex@$DomainRegex)`$|^$DNRegEx$|^$GUIDRegex$|^$SIDRegex$|^(?<name>$UsernameRegex)`$"
    $ss = Select-String -Pattern $sPattern -InputObject $InputString -AllMatches
    if ($ss -ne $null) {
        $hMatchInfoHashtable = Convert-MatchInfoToHashtable -InputObject $ss
        $sIdentity, $sType = if ($hMatchInfoHashtable.upn) {
            $hMatchInfoHashtable.upn, "upn"
        } elseif ($hMatchInfoHashtable.sid) {
            $hMatchInfoHashtable.sid, "sid"
        } elseif ($hMatchInfoHashtable.dn) {
            $hMatchInfoHashtable.dn, "dn"
        } elseif ($hMatchInfoHashtable.guid) {
            $hMatchInfoHashtable.guid, "guid"
        } elseif ($hMatchInfoHashtable.principalname) {
            $hMatchInfoHashtable.user, "principalname"
        } else {
            $hMatchInfoHashtable.name, "name"
        }
        $hResult = [ordered]@{
            Identity = $sIdentity
            Category = "ADObjectIdentity"
            Type = $sType
        }
        if ($hMatchInfoHashtable.domain) {
            $hResult.Server = $hMatchInfoHashtable.domain
        }
        $hResult.Details = $hMatchInfoHashtable
        return $hResult
    } else {
        return $null
    }
}