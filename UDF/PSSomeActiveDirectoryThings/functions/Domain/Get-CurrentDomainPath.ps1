function Get-CurrentDomainPath {
    <#
    .SYNOPSIS
        Returns the LDAP path of the current domain

    .DESCRIPTION
        Queries RootDSE for the defaultNamingContext and returns the full LDAP://
        path to the current domain.

    .OUTPUTS
        System.String. The LDAP path (e.g., "LDAP://DC=contoso,DC=com").

    .EXAMPLE
        $domainPath = Get-CurrentDomainPath

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    [System.DirectoryServices.DirectoryEntry] $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://RootDSE")
    return "LDAP://" + $de.Properties["defaultNamingContext"][0].ToString();
}