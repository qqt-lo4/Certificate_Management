function Split-DN {
    <#
    .SYNOPSIS
        Splits a distinguished name into path and domain parts

    .DESCRIPTION
        Separates a DN into the object path (before DC=) and the domain
        portion (DC=...) components.

    .PARAMETER DN
        The distinguished name to split.

    .OUTPUTS
        PSCustomObject with Path and Domain properties.

    .EXAMPLE
        Split-DN -DN "CN=User,OU=Users,DC=contoso,DC=com"
        # Returns: Path = "CN=User,OU=Users", Domain = "DC=contoso,DC=com"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [string]$DN
    )
    $iDC = $DN.IndexOf("DC=")
    if ($iDC -eq -1) {
        $iDC = $DN.IndexOf("dc=")
    }
    return [pscustomobject]@{
        Path = $DN.Substring(0, $iDC - 1)
        Domain = $DN.Substring($iDC)
    }
}
