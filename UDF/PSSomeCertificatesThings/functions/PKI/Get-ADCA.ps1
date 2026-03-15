function Get-ADCA {
    <#
    .SYNOPSIS
        Retrieves comprehensive Certificate Authority information from Active Directory

    .DESCRIPTION
        Gets detailed information about Certificate Authorities from Active Directory, including
        CA objects, enrollment services, DNS hostnames, and published certificate templates.
        Optionally filters by CA name or template names.

    .PARAMETER CANameFilter
        Regex filter to match against CA names.

    .PARAMETER TemplatesFilter
        Regex filter to match against certificate template names.

    .OUTPUTS
        [Array]. Array of hashtables with Name, dNSHostName, CertificateTemplates, CA, and EnrollmentService properties.

    .EXAMPLE
        Get-ADCA

    .EXAMPLE
        Get-ADCA -CANameFilter "CompanyCA"

    .EXAMPLE
        Get-ADCA -TemplatesFilter "WebServer"

    .EXAMPLE
        $cas = Get-ADCA
        $cas | ForEach-Object { Write-Host "$($_.Name) - $($_.dNSHostName)"; $_.CertificateTemplates }

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [string]$CANameFilter,
        [string]$TemplatesFilter
    )
    $aCA = Get-CA
    if ($CANameFilter) {
        $aCA = $aCA | Where-Object { $_.Name -match $CANameFilter }
    }
    $aEnrollmentServices = Get-CAEnrollmentServices
    $aResult = @()
    foreach ($oCA in $aCA) {
        $oEnrollmentServices = $aEnrollmentServices | Where-Object { $_.name -eq $oCA.name }
        $aTemplates = $oEnrollmentServices.certificateTemplates
        if ($TemplatesFilter) {
            $aTemplates = $aTemplates | Where-Object { $_ -match $TemplatesFilter }
        }
        $hItem = [ordered]@{
            Name = $oCA.name
            dNSHostName = $oEnrollmentServices.DNSHostName
            CertificateTemplates = $aTemplates | Sort-Object
            CA = $oCA
            EnrollmentService = $oEnrollmentServices
        }
        $aResult += $hItem
    }
    return $aResult
}
