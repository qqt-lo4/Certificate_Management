function Get-PublishedCertificateTemplates {
    <#
    .SYNOPSIS
        Retrieves certificate templates published on a Certificate Authority

    .DESCRIPTION
        Gets the list of certificate templates that are published and available on a specific
        Certificate Authority. Queries both the CA enrollment services and certificate templates
        from Active Directory.

    .PARAMETER CA
        Name of the Certificate Authority to query.

    .OUTPUTS
        [Array]. Array of certificate template objects published on the CA.

    .EXAMPLE
        Get-PublishedCertificateTemplates -CA "CompanyCA"

    .EXAMPLE
        $templates = Get-PublishedCertificateTemplates -CA "RootCA"
        $templates | Select-Object Name, displayName

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$CA
    )
    $aCATemplates = Get-CertificateTemplates
    $oCA = Get-CAEnrollmentServices | Where-Object { $_.Name -ieq $CA }
    $result = if ($oCA) {
        $aCATemplatesNames = $oCA.certificateTemplates
        $aCATemplates | Where-Object { $_.Name -iin $aCATemplatesNames }
    } else {
        @()
    }
    return $result
}
