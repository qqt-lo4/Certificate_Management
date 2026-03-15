function Get-ADDomainControllers {
    <#
    .SYNOPSIS
        Returns the domain controllers for a specified AD domain

    .DESCRIPTION
        Retrieves the list of domain controllers for a given domain within
        the current forest. Defaults to the current user's domain.

    .PARAMETER Domain
        The domain name to query. Defaults to $env:USERDNSDOMAIN.

    .OUTPUTS
        System.DirectoryServices.ActiveDirectory.DomainControllerCollection.

    .EXAMPLE
        Get-ADDomainControllers -Domain "contoso.com"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [string]$Domain = ($env:USERDNSDOMAIN)
    )
    $oDomain = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Domains | Where-Object { $_.Name -eq $Domain }
    return $oDomain.DomainControllers
}