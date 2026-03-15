function ConvertFrom-CategoryDN {
    <#
    .SYNOPSIS
        Extracts the CN value from a category distinguished name

    .DESCRIPTION
        Parses a distinguished name string and extracts the first CN (Common Name)
        component. Useful for extracting object category names from objectCategory
        DN values (e.g., "CN=Person,CN=Schema,CN=Configuration,DC=domain,DC=com").

    .PARAMETER DN
        The distinguished name string to parse. Must start with "CN=" or "cn=".

    .OUTPUTS
        [string]. The CN value extracted from the distinguished name.

    .EXAMPLE
        ConvertFrom-CategoryDN -DN "CN=Person,CN=Schema,CN=Configuration,DC=domain,DC=com"
        # Returns "Person"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [ValidatePattern("^(CN|cn)=(?<cn>[^,]+),.+$")]
        [string]$DN
    )
    $oMatchInfo = $DN | Select-String -Pattern "^(CN|cn)=(?<cn>[^,]+),.+$"
    return ($oMatchInfo.Matches.Groups | Where-Object { $_.Name -eq "cn" }).Value
}
