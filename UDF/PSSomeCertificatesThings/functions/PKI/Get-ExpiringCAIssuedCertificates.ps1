function Get-ExpiringCAIssuedCertificates {
    <#
    .SYNOPSIS
        Gets issued CA certificates that expire within a specified number of days.

    .DESCRIPTION
        Queries issued certificates for existing Certificate Authorities back to the maximum
        validity period of the selected templates, optionally filters by CA and template regex,
        keeps the newest certificate among same-template/same-CN records with equal or
        subset-related SAN sets, and then filters the winners by expiration window.

    .PARAMETER Credential
        Credentials used to connect to each CA server.

    .PARAMETER DaysAhead
        Include certificates expiring within this many days. Default: 30.

    .PARAMETER TemplateFilter
        Optional regular expression matched against certificate template names.

    .PARAMETER ExcludedTemplateFilter
        Optional regular expression for certificate template names to exclude.

    .PARAMETER CANameFilter
        Optional regular expression matched against CA names.

    .PARAMETER MaxResultsPerCA
        Maximum number of issued certificates to retrieve from each CA. Default: unlimited.

    .PARAMETER IncludeCertificate
        Include the complete certificate as a System.Security.Cryptography.X509Certificates.X509Certificate2 object.

    .OUTPUTS
        [PSCustomObject[]] Certificate records with CAName, CommonName, SAN, CertificateTemplate,
        IssuedOn, NotAfter, DaysRemaining, RequesterName, SerialNumber, and CertificateHash.

    .EXAMPLE
        $credential = Get-Credential
        Get-ExpiringCAIssuedCertificates -Credential $credential -DaysAhead 30 `
            -TemplateFilter '^(WebServer|VPN)$'
    #>
    [CmdletBinding()]
    Param(
        [PSCredential]$Credential,

        [ValidateRange(1, 36500)]
        [int]$DaysAhead = 30,

        [string]$TemplateFilter,

        [string]$ExcludedTemplateFilter,

        [string]$CANameFilter,

        [ValidateRange(1, [int]::MaxValue)]
        [int]$MaxResultsPerCA = [int]::MaxValue,

        [switch]$IncludeCertificate
    )

    foreach ($sFilter in @($TemplateFilter, $ExcludedTemplateFilter, $CANameFilter) | Where-Object { $_ }) {
        try {
            $null = [regex]::new($sFilter)
        } catch {
            throw "Invalid regular expression '$sFilter': $_"
        }
    }

    $aCAs = @(Get-CAEnrollmentServices -Existing)
    if ($CANameFilter) {
        $aCAs = @($aCAs | Where-Object { $_.Name -match $CANameFilter })
    }

    $dtNow = Get-Date
    $dtDeadline = $dtNow.AddDays($DaysAhead)
    $hCandidatesByIdentity = @{}
    $iCertificateDecodeFailures = 0

    $aSelectedTemplates = @(Get-CertificateTemplateDetails -NameFilter $TemplateFilter)
    if ($ExcludedTemplateFilter) {
        $aSelectedTemplates = @($aSelectedTemplates | Where-Object { $_.name -notmatch $ExcludedTemplateFilter })
    }
    if ($aSelectedTemplates.Count -eq 0) {
        if ($TemplateFilter -or $ExcludedTemplateFilter) { return @() }
        throw "No certificate templates were found; cannot determine the history search period."
    }

    $aTemplatesWithUnknownValidity = @($aSelectedTemplates | Where-Object { -not $_.validityDays })
    $bCanBoundTemplateHistory = ($aTemplatesWithUnknownValidity.Count -eq 0)
    $dtIssuedOnFrom = if ($bCanBoundTemplateHistory) {
        $iMaxTemplateLifetimeDays = ($aSelectedTemplates | Measure-Object -Property validityDays -Maximum).Maximum
        $dtNow.AddDays(-[int]$iMaxTemplateLifetimeDays)
    } else {
        Write-Warning "At least one selected template has unknown validity; searching without an issuance-date cutoff."
        $null
    }

    foreach ($oCA in $aCAs) {
        $sComputerName = ($oCA.dNSHostName -split '\.')[0]
        if (-not $sComputerName) {
            Write-Warning "Skipping '$($oCA.Name)': no CA server hostname is configured."
            continue
        }

        try {
            $hIssuedCertificateParams = @{
                CAName = $oCA.Name
                ComputerName = $sComputerName
                Credential = $Credential
                MaxResults = $MaxResultsPerCA
                IncludeSAN = $true
                IncludeRawCertificate = $IncludeCertificate.IsPresent
            }
            if ($null -ne $dtIssuedOnFrom) { $hIssuedCertificateParams.IssuedOnFrom = $dtIssuedOnFrom }
            $aIssuedCertificates = @(Get-CAIssuedCertificates @hIssuedCertificateParams)
        } catch {
            Write-Warning "Could not query issued certificates from '$($oCA.Name)': $_"
            continue
        }

        foreach ($oCertificate in $aIssuedCertificates) {
            if (-not $oCertificate.NotAfter) { continue }
            try {
                $dtNotAfter = [datetime]$oCertificate.NotAfter
            } catch {
                continue
            }
            if ($TemplateFilter -and $oCertificate.CertificateTemplate -notmatch $TemplateFilter) { continue }
            if ($ExcludedTemplateFilter -and $oCertificate.CertificateTemplate -match $ExcludedTemplateFilter) { continue }

            $sTemplateIdentity = ([string]$oCertificate.CertificateTemplate).Trim().ToUpperInvariant()
            $sCommonNameIdentity = ([string]$oCertificate.CommonName).Trim().ToUpperInvariant()
            $hSANIdentity = @{}
            if ($oCertificate.SAN -and $oCertificate.SAN.Count -gt 0) {
                foreach ($sSANType in @($oCertificate.SAN.Keys | Sort-Object)) {
                    foreach ($sSANValue in @($oCertificate.SAN[$sSANType])) {
                        $sSANKey = "{0}:{1}" -f ([string]$sSANType).Trim().ToUpperInvariant(), ([string]$sSANValue).Trim().ToUpperInvariant()
                        $hSANIdentity[$sSANKey] = $true
                    }
                }
            }
            if ($sCommonNameIdentity) {
                $sIdentity = ConvertTo-Json -InputObject @($sTemplateIdentity, $sCommonNameIdentity) -Compress
            } elseif ($hSANIdentity.Count -gt 0) {
                $sIdentity = "TEMPLATE:$sTemplateIdentity|SAN"
            } else {
                $sFallbackIdentity = if ($oCertificate.SerialNumber) { $oCertificate.SerialNumber } else { $oCertificate.RequestID }
                $sIdentity = "REQUEST:$($oCA.Name):$sFallbackIdentity"
            }

            $aCandidateDates = @()
            foreach ($oIssuedDate in @($oCertificate.ResolvedWhen, $oCertificate.NotBefore)) {
                if (-not $oIssuedDate) { continue }
                try {
                    $aCandidateDates += [datetime]$oIssuedDate
                } catch {}
            }
            $dtIssuedOn = if ($aCandidateDates.Count -gt 0) {
                ($aCandidateDates | Measure-Object -Maximum).Maximum
            } else {
                [datetime]::MinValue
            }

            $oFullCertificate = $null
            if ($IncludeCertificate) {
                try {
                    $oRawCertificate = $oCertificate.RawCertificate
                    if ($oRawCertificate -is [byte[]] -and $oRawCertificate.Length -gt 0 -and $oRawCertificate[0] -eq 0x30) {
                        $aRawCertificate = $oRawCertificate
                    } else {
                        $sEncodedCertificate = if ($oRawCertificate -is [byte[]]) {
                            [System.Text.Encoding]::ASCII.GetString($oRawCertificate)
                        } else {
                            [string]$oRawCertificate
                        }
                        $sEncodedCertificate = $sEncodedCertificate -replace '-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s', ''
                        $aRawCertificate = [Convert]::FromBase64String($sEncodedCertificate)
                    }
                    if ($aRawCertificate.Length -gt 0) {
                        $oFullCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$aRawCertificate)
                    } else {
                        $iCertificateDecodeFailures++
                    }
                } catch {
                    $iCertificateDecodeFailures++
                    Write-Verbose "Could not create X509Certificate2 for request $($oCertificate.RequestID): $_"
                }
            }

            $oCandidate = [PSCustomObject]@{
                CAName = $oCA.Name
                CommonName = $oCertificate.CommonName
                SAN = $oCertificate.SAN
                SANIdentity = $hSANIdentity
                CertificateTemplate = $oCertificate.CertificateTemplate
                IssuedOn = $dtIssuedOn
                NotAfter = $dtNotAfter
                DaysRemaining = $null
                RequesterName = $oCertificate.RequesterName
                SerialNumber = $oCertificate.SerialNumber
                CertificateHash = $oCertificate.CertificateHash
            }
            if ($IncludeCertificate) {
                $oCandidate | Add-Member -MemberType NoteProperty -Name Certificate -Value $oFullCertificate
            }

            if (-not $hCandidatesByIdentity.ContainsKey($sIdentity)) {
                $hCandidatesByIdentity[$sIdentity] = @()
            }
            $hCandidatesByIdentity[$sIdentity] += $oCandidate
        }
    }

    $aExpiringCertificates = @()
    foreach ($aCandidates in $hCandidatesByIdentity.Values) {
        $iCandidateCount = $aCandidates.Count
        $aParents = @(for ($iCandidate = 0; $iCandidate -lt $iCandidateCount; $iCandidate++) { $iCandidate })

        for ($iLeft = 0; $iLeft -lt $iCandidateCount; $iLeft++) {
            for ($iRight = $iLeft + 1; $iRight -lt $iCandidateCount; $iRight++) {
                if ($aCandidates[$iLeft].SANIdentity.Count -eq 0 -and
                    $aCandidates[$iRight].SANIdentity.Count -eq 0 -and
                    $aCandidates[$iLeft].CertificateTemplate -ine $aCandidates[$iRight].CertificateTemplate) {
                    continue
                }

                $bLeftInRight = $true
                foreach ($sSANKey in $aCandidates[$iLeft].SANIdentity.Keys) {
                    if (-not $aCandidates[$iRight].SANIdentity.ContainsKey($sSANKey)) {
                        $bLeftInRight = $false
                        break
                    }
                }

                $bRightInLeft = $true
                foreach ($sSANKey in $aCandidates[$iRight].SANIdentity.Keys) {
                    if (-not $aCandidates[$iLeft].SANIdentity.ContainsKey($sSANKey)) {
                        $bRightInLeft = $false
                        break
                    }
                }
                if (-not ($bLeftInRight -or $bRightInLeft)) { continue }

                $iLeftRoot = $iLeft
                while ($aParents[$iLeftRoot] -ne $iLeftRoot) { $iLeftRoot = $aParents[$iLeftRoot] }
                $iRightRoot = $iRight
                while ($aParents[$iRightRoot] -ne $iRightRoot) { $iRightRoot = $aParents[$iRightRoot] }
                if ($iLeftRoot -ne $iRightRoot) { $aParents[$iRightRoot] = $iLeftRoot }
            }
        }

        $hSANFamilies = @{}
        for ($iCandidate = 0; $iCandidate -lt $iCandidateCount; $iCandidate++) {
            $iRoot = $iCandidate
            while ($aParents[$iRoot] -ne $iRoot) { $iRoot = $aParents[$iRoot] }
            if (-not $hSANFamilies.ContainsKey($iRoot)) { $hSANFamilies[$iRoot] = @() }
            $hSANFamilies[$iRoot] += $aCandidates[$iCandidate]
        }

        foreach ($aSANFamily in $hSANFamilies.Values) {
            $oNewestCertificate = $aSANFamily[0]
            foreach ($oCandidate in $aSANFamily | Select-Object -Skip 1) {
                if ($oCandidate.IssuedOn -gt $oNewestCertificate.IssuedOn -or
                    ($oCandidate.IssuedOn -eq $oNewestCertificate.IssuedOn -and $oCandidate.NotAfter -gt $oNewestCertificate.NotAfter)) {
                    $oNewestCertificate = $oCandidate
                }
            }

            foreach ($oCandidate in $aSANFamily) {
                if (-not [object]::ReferenceEquals($oCandidate.Certificate, $oNewestCertificate.Certificate) -and
                    $oCandidate.Certificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                    $oCandidate.Certificate.Dispose()
                }
            }

            if ($oNewestCertificate.NotAfter -le $dtNow -or $oNewestCertificate.NotAfter -gt $dtDeadline) {
                if ($oNewestCertificate.Certificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                    $oNewestCertificate.Certificate.Dispose()
                }
                continue
            }
            $oNewestCertificate.DaysRemaining = [int][Math]::Ceiling(($oNewestCertificate.NotAfter - $dtNow).TotalDays)
            $oNewestCertificate.SANIdentity = $null
            if ($oNewestCertificate.IssuedOn -eq [datetime]::MinValue) { $oNewestCertificate.IssuedOn = $null }
            $aExpiringCertificates += $oNewestCertificate
        }
    }

    if ($iCertificateDecodeFailures -gt 0) {
        Write-Warning "Could not decode the complete certificate for $iCertificateDecodeFailures request(s). Their Certificate property is null."
    }

    return @($aExpiringCertificates | Sort-Object NotAfter)
}