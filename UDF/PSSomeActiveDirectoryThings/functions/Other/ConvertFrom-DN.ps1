function ConvertFrom-DN {
    <#
    .SYNOPSIS
        Extracts the domain name from a distinguished name

    .DESCRIPTION
        Parses the DC (Domain Component) parts of a distinguished name and joins
        them with dots to form a fully qualified domain name.

    .PARAMETER DN
        The distinguished name string containing DC components.

    .OUTPUTS
        [string]. The domain name (e.g., "domain.example.com").

    .EXAMPLE
        ConvertFrom-DN -DN "CN=John,OU=Users,DC=corp,DC=example,DC=com"
        # Returns "corp.example.com"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [ValidatePattern("((DC|dc)=)(?<name>[A-Za-z._0-9-]+)")]
        [string]$DN
    )
    $oMatchInfo = $DN | Select-String -Pattern "((DC|dc)=)(?<name>[A-Za-z._0-9-]+)" -AllMatches
    return (($oMatchInfo.Matches.Groups | Where-Object { $_.Name -eq "name" }).Value) -join "."
}
