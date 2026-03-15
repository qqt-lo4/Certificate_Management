function Get-CertificateTemplates {
    <#
    .SYNOPSIS
        Retrieves all certificate templates from Active Directory

    .DESCRIPTION
        Gets all certificate template objects from the Certificate Templates container
        in the Active Directory forest configuration.

    .OUTPUTS
        [Array]. Array of certificate template objects.

    .EXAMPLE
        Get-CertificateTemplates

    .EXAMPLE
        $templates = Get-CertificateTemplates
        $templates | Select-Object Name, displayName

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    $sForestName = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name 
    $oForest = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$sForestName")
    $sForestDN = $oForest.distinguishedName
    $sCertificateTemplatesDN = "LDAP://$sForestName/CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$sForestDN"
    return Get-ADContainerObjects -ContainerDN $sCertificateTemplatesDN
}