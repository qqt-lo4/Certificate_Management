function Test-StringIsDNSName {
    <#
    .SYNOPSIS
        Tests if a string is a valid DNS name

    .DESCRIPTION
        Validates whether a string matches the DNS name format using Unicode-aware
        regex (supports internationalized domain names).

    .PARAMETER InputString
        The string to test.

    .OUTPUTS
        [Hashtable] or $null. Contains Type, Category, and Details if valid.

    .EXAMPLE
        Test-StringIsDNSName "server.domain.com"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

    Param(
        [parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [string]$InputString
    )
    $sDNSAllowedChar = "[\p{L}\p{Pc}\p{Pd}\p{Nd}]"
    $sRegex = "^(?<dnspart>$sDNSAllowedChar{1,63})(\.(?<dnspart>$sDNSAllowedChar{1,63}))*$"
    $ss = Select-String -InputObject $InputString -Pattern $sRegex -AllMatches
    if ($ss) {
        return @{
            Type = "DNSObject"
            Category = "DNSObject"
            Details = $ss
        }
    } else {
        return $null
    }
}