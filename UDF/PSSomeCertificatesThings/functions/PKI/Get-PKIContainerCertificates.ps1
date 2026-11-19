function Get-PKIContainerCertificates {
    <#
    .SYNOPSIS
        Reads and decodes certificate values from a PKI Active Directory container.

    .PARAMETER ContainerDN
        LDAP path of the container to search.

    .PARAMETER Filter
        LDAP filter. Defaults to certificationAuthority objects.

    .PARAMETER CertProperty
        Binary certificate property to decode. Defaults to cACertificate.

    .PARAMETER SourceLabel
        Label prepended to each returned object's source property.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$ContainerDN,
        [string]$Filter = '(objectClass=certificationAuthority)',
        [string]$CertProperty = 'cACertificate',
        [Parameter(Mandatory)]
        [string]$SourceLabel
    )

    $oSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$ContainerDN)
    $oSearcher.Filter = $Filter
    $oSearcher.PageSize = 100
    $oSearcher.PropertiesToLoad.AddRange(@('name', 'cn', $CertProperty, 'whenCreated', 'whenChanged'))

    $aResults = @()
    $oSearchResults = $null
    try {
        $oSearchResults = $oSearcher.FindAll()
        foreach ($oResult in $oSearchResults) {
            $sName = [string]$oResult.Properties['cn'][0]
            $aCertBytes = $oResult.Properties[$CertProperty]

            if ($aCertBytes -and $aCertBytes.Count -gt 0) {
                foreach ($certData in $aCertBytes) {
                    $oCertInfo = ConvertFrom-BinaryCertificate -Bytes ([byte[]]$certData) -Source "$SourceLabel/$sName"
                    if ($oCertInfo) { $aResults += $oCertInfo }
                }
            } else {
                $aResults += [PSCustomObject][ordered]@{
                    source = "$SourceLabel/$sName"
                    subject = $null
                    issuer = $null
                    notBefore = $oResult.Properties['whencreated'][0]
                    notAfter = $null
                    serialNumber = $null
                    thumbprint = $null
                    signatureAlgorithm = $null
                    keySize = $null
                    version = $null
                    hasPrivateKey = $null
                    rawData = $null
                }
            }
        }
    } catch {
        Write-Verbose "Failed to query $ContainerDN : $_"
    } finally {
        if ($oSearchResults) { $oSearchResults.Dispose() }
        $oSearcher.Dispose()
    }
    return $aResults
}
