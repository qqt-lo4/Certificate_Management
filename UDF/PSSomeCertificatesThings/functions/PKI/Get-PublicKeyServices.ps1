function Get-PublicKeyServices {
    <#
    .SYNOPSIS
        Retrieves the Public Key Services container from Active Directory

    .DESCRIPTION
        Gets the Public Key Services container from the Active Directory forest configuration.
        This container holds PKI-related objects including Certificate Templates, Enrollment Services, and CAs.

    .OUTPUTS
        [PSCustomObject]. The Public Key Services directory entry object.

    .EXAMPLE
        Get-PublicKeyServices

    .EXAMPLE
        $pks = Get-PublicKeyServices
        $pks.distinguishedName

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    $sForestName = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name 
    $oForest = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$sForestName")
    $sForestDN = $oForest.distinguishedName
    $oConfiguration = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$sForestName/CN=Public Key Services,CN=Services,CN=Configuration,$sForestDN")
    return $oConfiguration | ConvertTo-ADObject
}