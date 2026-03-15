function Group-DNByDomain {
    <#
    .SYNOPSIS
        Groups a list of distinguished names by domain

    .DESCRIPTION
        Takes a list of distinguished names and groups them by their domain
        component (DC values). Returns a hashtable where keys are domain names
        and values are the corresponding distinguished names.

    .PARAMETER DNList
        The list of distinguished names to group.

    .OUTPUTS
        [hashtable]. Keys are domain names, values are the distinguished names belonging to each domain.

    .EXAMPLE
        $group = Get-ADObject -Identity "CN=Test,OU=Groups,DC=lan,DC=example,DC=com"
        Group-DNByDomain -DNList $group.member

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string[]]$DNList
    )
    return $DNList | Group-Object -Property {
        $ss = Select-String -InputObject $_ -Pattern "DC=(?<dc>[^,]+)" -AllMatches
        ($ss.Matches.Groups | Where-Object { $_.name -eq "dc" }).Value -join "."
    } -AsHashTable
}
