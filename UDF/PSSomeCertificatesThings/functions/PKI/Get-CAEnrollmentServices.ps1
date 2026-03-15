function Get-CAEnrollmentServices {
    <#
    .SYNOPSIS
        Retrieves CA Enrollment Services from Active Directory

    .DESCRIPTION
        Gets Certificate Authority Enrollment Services objects from the Enrollment Services container
        in the Active Directory forest configuration. Optionally filters by server hostname or name pattern.

    .PARAMETER Server
        Filter enrollment services by DNS hostname of the server.

    .PARAMETER NameFilter
        Regex filter to match against enrollment service names.

    .OUTPUTS
        [Array]. Array of enrollment service objects.

    .EXAMPLE
        Get-CAEnrollmentServices

    .EXAMPLE
        Get-CAEnrollmentServices -Server "ca-server.example.com"

    .EXAMPLE
        Get-CAEnrollmentServices -NameFilter "CompanyCA"

    .EXAMPLE
        $services = Get-CAEnrollmentServices
        $services | Select-Object Name, dNSHostName

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Position = 0)]
        [string]$Server,
        [string]$NameFilter
    )

    $oForest = Get-ADForest
    $sEnrollmentServicesDN = "LDAP://$($oForest.AdditionalProperties.ForestName)/CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$($oForest.distinguishedName)"
    $aEnrollmentServices = Get-ADContainerObjects -ContainerDN $sEnrollmentServicesDN
    if ($Server) {
        $aEnrollmentServices = $aEnrollmentServices | Where-Object { $_.dNSHostName -ieq $Server }
    }
    if ($NameFilter) {
        $aEnrollmentServices = $aEnrollmentServices | Where-Object { $_.Name -match $NameFilter }
    }
    return $aEnrollmentServices
}