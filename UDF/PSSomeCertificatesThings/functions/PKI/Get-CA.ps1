function Get-CA {
    <#
    .SYNOPSIS
        Retrieves Certificate Authorities from Active Directory

    .DESCRIPTION
        Gets Certificate Authority objects from the AIA (Authority Information Access) container
        in the Active Directory forest configuration. Optionally filters CAs by name.

    .PARAMETER Filter
        Optional regex filter to match against CA names.

    .OUTPUTS
        [Array]. Array of CA objects.

    .EXAMPLE
        Get-CA

    .EXAMPLE
        Get-CA -Filter "CompanyCA"

    .EXAMPLE
        $cas = Get-CA
        $cas | Select-Object Name, distinguishedName

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [string]$Filter
    )

    $oForest = Get-ADForest
    $sAIADN = "LDAP://$($oForest.AdditionalProperties.ForestName)/CN=AIA,CN=Public Key Services,CN=Services,CN=Configuration,$($oForest.distinguishedName)"
    $aAIA = Get-ADContainerObjects -ContainerDN $sAIADN
    if ($Filter) {
        return $aAIA | Where-Object { $_.Name -match $Filter }
    } else {
        return $aAIA
    }
}