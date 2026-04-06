function Export-PKIConfiguration {
    <#
    .SYNOPSIS
        Exports Microsoft PKI configuration into a navigable HTML report.

    .DESCRIPTION
        Collects certificate templates, CA enrollment services, and recently issued
        certificates from enterprise Certificate Authorities and generates a single
        HTML file using the PSSomeWebUIThings module.

        By default, auto-discovers existing CAs via AD enrollment services.
        Use -Credential to authenticate to the CA servers for certificate retrieval.

    .PARAMETER FolderPath
        Local destination folder for the HTML report. Must exist.

    .PARAMETER Credential
        Credentials for remote execution on CA servers (for issued certificates query).
        If not specified, uses current user credentials.

    .PARAMETER CANameFilter
        Regex filter to restrict which CAs to export. Optional.

    .PARAMETER MaxIssuedCerts
        Maximum number of recently issued certificates per CA. Default: 100.

    .OUTPUTS
        [System.IO.FileInfo] The generated HTML file.

    .EXAMPLE
        Export-PKIConfiguration -FolderPath "C:\Exports"

    .EXAMPLE
        Export-PKIConfiguration -FolderPath "C:\Exports" -Credential (Get-Credential) -MaxIssuedCerts 200

    .EXAMPLE
        Export-PKIConfiguration -FolderPath "C:\Exports" -CANameFilter "SubCA"

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-03-30) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$FolderPath,

        [PSCredential]$Credential,

        [string]$CANameFilter,

        [int]$MaxIssuedCerts = 100
    )

    Begin {
        if (-not (Test-Path $FolderPath -PathType Container)) {
            throw "Folder does not exist: $FolderPath"
        }
    }

    Process {
        $sTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $sFileName = "Export_PKI_${sTimestamp}.html"
        $sFilePath = Join-Path $FolderPath $sFileName
        $sCallerName = "Exporting PKI Configuration"

        $iTotal = 0
        $iTocIndex = 0
        $aSectionFiles = @()

        # --- Discover existing CAs ---
        Write-Progress -Activity $sCallerName -Status "Discovering Certificate Authorities..." -PercentComplete 2
        $hEnrollParams = @{ Existing = $true }
        if ($CANameFilter) { $hEnrollParams['NameFilter'] = $CANameFilter }
        try {
            $aEnrollmentServices = @(Get-CAEnrollmentServices @hEnrollParams)
        } catch {
            Write-Warning "$sCallerName : Get-CAEnrollmentServices - $_"
            $aEnrollmentServices = @()
        }

        if ($aEnrollmentServices.Count -eq 0) {
            Write-Warning "$sCallerName : No existing CA enrollment services found."
            return
        }

        Write-Host "Found $($aEnrollmentServices.Count) CA(s): $($aEnrollmentServices.Name -join ', ')" -ForegroundColor Cyan

        # --- Certificate Authorities section ---
        if ($aEnrollmentServices.Count -gt 0) {
            $sId = "sec_$iTocIndex"
            $iTocIndex++
            $sSectionFile = ConvertTo-HTMLSection -Title "Certificate Authorities" -Id $sId -Data $aEnrollmentServices `
                -Tab "authorities" -NameProperty 'name' -DetectAllColumns
            $aSectionFiles += $sSectionFile
            $iTotal += $aEnrollmentServices.Count
        }

        # --- AD Certificate Templates with decoded details (forest-wide) ---
        Write-Progress -Activity $sCallerName -Status "Collecting certificate templates from AD..." -PercentComplete 5
        try {
            $aAllTemplates = @(Get-CertificateTemplateDetails)
        } catch {
            Write-Warning "$sCallerName : Get-CertificateTemplateDetails - $_"
            $aAllTemplates = @()
        }

        if ($aAllTemplates.Count -gt 0) {
            $sId = "sec_$iTocIndex"
            $iTocIndex++
            $sSectionFile = ConvertTo-HTMLSection -Title "Certificate Templates (AD)" -Id $sId -Data $aAllTemplates `
                -Tab "templates" -NameProperty 'name' -DetectAllColumns
            $aSectionFiles += $sSectionFile
            $iTotal += $aAllTemplates.Count
        }

        # --- Per-CA exports ---
        $iCAIndex = 0
        $iCACount = $aEnrollmentServices.Count

        foreach ($oES in $aEnrollmentServices) {
            $iCAIndex++
            $sCAName = $oES.Name
            $sCAHost = $oES.dNSHostName
            # Use short hostname for ComputerName
            $sComputerName = ($sCAHost -split '\.')[0]

            # --- Published templates on this CA (filtered from detailed templates) ---
            $iPercent = 10 + [int](($iCAIndex / $iCACount) * 35)
            Write-Progress -Activity $sCallerName -Status "$sCAName - Published templates..." -PercentComplete $iPercent

            $aPublishedNames = @($oES.certificateTemplates)
            $aPublished = @($aAllTemplates | Where-Object { $_.name -in $aPublishedNames })

            if ($aPublished.Count -gt 0) {
                $sId = "sec_$iTocIndex"
                $iTocIndex++
                $sSectionFile = ConvertTo-HTMLSection -Title "Published Templates" -Id $sId -Data $aPublished `
                    -Tab "templates" -Context $sCAName -NameProperty 'name' -DetectAllColumns
                $aSectionFiles += $sSectionFile
                $iTotal += $aPublished.Count
            }

            # --- Issued certificates ---
            $iPercent = 45 + [int](($iCAIndex / $iCACount) * 45)
            Write-Progress -Activity $sCallerName -Status "$sCAName - Issued certificates (last $MaxIssuedCerts)..." -PercentComplete $iPercent

            $hCertParams = @{
                CAName     = $sCAName
                ComputerName = $sComputerName
                MaxResults = $MaxIssuedCerts
            }
            if ($Credential) { $hCertParams['Credential'] = $Credential }

            try {
                $aIssued = @(Get-CAIssuedCertificates @hCertParams)
            } catch {
                Write-Warning "$sCallerName : $sCAName/IssuedCertificates - $_"
                $aIssued = @()
            }

            if ($aIssued.Count -gt 0) {
                $sId = "sec_$iTocIndex"
                $iTocIndex++
                $sSectionFile = ConvertTo-HTMLSection -Title "Issued Certificates (last $MaxIssuedCerts)" -Id $sId -Data $aIssued `
                    -Tab "certificates" -Context $sCAName -NameProperty 'CommonName' -DetectAllColumns
                $aSectionFiles += $sSectionFile
                $iTotal += $aIssued.Count
            }
        }

        # --- PKI AD Objects (AIA, NTAuth, CDP, KRA, Root CAs) ---
        Write-Progress -Activity $sCallerName -Status "Collecting PKI AD objects (AIA, NTAuth, CDP, KRA)..." -PercentComplete 92

        $aPKITypes = @(
            @{ Type = 'AIA';    Title = 'AIA (Intermediate CA Certificates)' }
            @{ Type = 'NTAuth'; Title = 'NTAuthCertificates (Client Auth Trust)' }
            @{ Type = 'RootCA'; Title = 'Root CAs (Trusted Root Store)' }
            @{ Type = 'KRA';    Title = 'Key Recovery Agents' }
            @{ Type = 'CDP';    Title = 'CRL Distribution Points' }
        )

        foreach ($oPKIType in $aPKITypes) {
            try {
                $aData = @(Get-PKIADObjects -Type $oPKIType.Type)
                if ($aData.Count -gt 0) {
                    $sId = "sec_$iTocIndex"
                    $iTocIndex++
                    $sSectionFile = ConvertTo-HTMLSection -Title $oPKIType.Title -Id $sId -Data $aData `
                        -Tab "authorities" -NameProperty 'subject' -DetectAllColumns
                    $aSectionFiles += $sSectionFile
                    $iTotal += $aData.Count
                }
            } catch {
                Write-Warning "$sCallerName : $($oPKIType.Title) - $_"
            }
        }

        # ===== GENERATE HTML REPORT =====
        Write-Progress -Activity $sCallerName -Status "Generating HTML report..." -PercentComplete 95

        $aTabs = @("authorities", "templates", "certificates")

        $oReport = New-HTMLReport -Title "PKI Export - $sTimestamp" `
            -Brand "PKI Export" `
            -DeviceInfo "Microsoft ADCS" `
            -SectionFiles $aSectionFiles `
            -Tabs $aTabs `
            -AccentColor "#2e7d32" `
            -FilePath $sFilePath `
            -ObjectCount $iTotal

        Write-Progress -Activity $sCallerName -Completed

        Write-Host "PKI configuration exported: $sFilePath ($iTotal objects)" -ForegroundColor Green

        return $oReport
    }
}
