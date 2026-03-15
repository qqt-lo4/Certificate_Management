function Get-CurrentADForestDomains {
    <#
    .SYNOPSIS
        Returns all domains in the current AD forest

    .DESCRIPTION
        Retrieves the list of domains belonging to the current Active Directory forest.

    .OUTPUTS
        System.DirectoryServices.ActiveDirectory.DomainCollection. The forest domains.

    .EXAMPLE
        $domains = Get-CurrentADForestDomains

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    $oForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    return $oForest.Domains
}