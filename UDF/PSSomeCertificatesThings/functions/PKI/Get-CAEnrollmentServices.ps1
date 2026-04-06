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

    .PARAMETER Existing
        If specified, only returns enrollment services whose DNS hostname resolves
        successfully. Filters out decommissioned CAs that still have AD objects.

    .OUTPUTS
        [Array]. Array of enrollment service objects.

    .EXAMPLE
        Get-CAEnrollmentServices

    .EXAMPLE
        Get-CAEnrollmentServices -Existing

    .EXAMPLE
        Get-CAEnrollmentServices -Server "ca-server.example.com"

    .EXAMPLE
        Get-CAEnrollmentServices -NameFilter "CompanyCA"

    .EXAMPLE
        $services = Get-CAEnrollmentServices
        $services | Select-Object Name, dNSHostName

    .NOTES
        Author  : Loïc Ade
        Version : 1.1.0

        1.1.0 (2026-03-30) - Added -Existing switch to filter out decommissioned CAs
        1.0.0 - Initial version
    #>
    Param(
        [Parameter(Position = 0)]
        [string]$Server,
        [string]$NameFilter,
        [switch]$Existing
    )

    $oForest = Get-ADForest
    $sEnrollmentServicesDN = "LDAP://$($oForest.AdditionalProperties.ForestName)/CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$($oForest.distinguishedName)"
    $aProperties = @(
        'name', 'displayName', 'dNSHostName', 'cACertificateDN',
        'certificateTemplates', 'flags',
        'whenCreated', 'whenChanged'
    )
    $aEnrollmentServices = Get-ADContainerObjects -ContainerDN $sEnrollmentServicesDN -Properties $aProperties
    if ($Server) {
        $aEnrollmentServices = $aEnrollmentServices | Where-Object { $_.dNSHostName -ieq $Server }
    }
    if ($NameFilter) {
        $aEnrollmentServices = $aEnrollmentServices | Where-Object { $_.Name -match $NameFilter }
    }
    if ($Existing) {
        $aEnrollmentServices = @($aEnrollmentServices | Where-Object {
            try {
                Resolve-DnsName -Name $_.dNSHostName -ErrorAction Stop | Out-Null
                $true
            } catch {
                Write-Verbose "Filtering out '$($_.Name)': DNS resolution failed for '$($_.dNSHostName)'"
                $false
            }
        })
    }
    return $aEnrollmentServices
}