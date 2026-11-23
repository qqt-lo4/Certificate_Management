function Test-PKIHealth {
    <#
    .SYNOPSIS
        Checks AD CS inventory, CA certificates and referenced CRL endpoints.

    .DESCRIPTION
        Reads CA inventory and CA certificates from Active Directory.

        Checks only CRL endpoints referenced by:
            - certificate CDP extensions
            - certificate Freshest CRL extensions
            - active CA CDP URLs from the CA request interface
            - Freshest CRL extensions in validated base CRLs

        Existing AD CDP objects are not evaluated merely because
        they exist.

        LDAP CRL publications are checked only when their LDAP URL
        is discovered as a referenced endpoint.

        Does not query the CA administration interface.

        Delta CRL URLs are discovered automatically from the
        FreshestCRLUrls property returned by Get-CRL.

        A missing reference is not replaced with a guessed filename.

    .PARAMETER ExpiringWithinDays
        Warning threshold for CA certificate expiration.
        Default: 30 days.

    .PARAMETER CRLWarningRemainingPercent
        Fallback warning threshold when the CRL has no usable publication window.
        Forwarded to Get-CRL. Default: 5.

    .PARAMETER CRLCriticalRemainingPercent
        Fallback critical threshold when the CRL has no usable publication window.
        Forwarded to Get-CRL. Default: 2.

    .PARAMETER DownloadTimeoutSeconds
        Timeout per CRL endpoint download.
        Default: 8 seconds.

    .OUTPUTS
        PSCustomObject[] with:
            Status
            Authority
            Check
            Details
            URL
            ThisUpdate
            NextUpdate
            NextPublish
            DaysRemaining
            SignatureStatus

    .NOTES
        Dependencies:
            Get-ADCA
            Get-PKIADObjects
            Get-CertificateURL
            Get-PKICARevocationUrls
            Get-CRL
            New-PKIHealthFinding
            Test-PKICACertificate
            Test-PKIAuthorityMetadata

        Get-CRL must be the enriched version using Get-CRLHealthData.

        CRL threshold policy remains delegated to Get-CRL and
        Test-CertificateRevocationList.

        Active CA CDP discovery uses the CA request interface.

        No raw AD CDP object is checked unless its endpoint
        is referenced by the inspected certificates, CRLs or CA.

        Coverage is limited to discovered references and reachable CAs.
    #>

    [CmdletBinding()]
    Param(
        [ValidateRange(1, 365)]
        [int]$ExpiringWithinDays = 30,

        [ValidateRange(1, 99)]
        [int]$CRLWarningRemainingPercent = 5,

        [ValidateRange(0, 98)]
        [int]$CRLCriticalRemainingPercent = 2,

        [ValidateRange(1, 120)]
        [int]$DownloadTimeoutSeconds = 8
    )

    if (
        $CRLCriticalRemainingPercent -ge
        $CRLWarningRemainingPercent
    ) {
        throw (
            'CRLCriticalRemainingPercent must be lower than ' +
            'CRLWarningRemainingPercent.'
        )
    }

    $aFindings = [System.Collections.Generic.List[object]]::new()

    $aCertificates = [System.Collections.Generic.List[object]]::new()

    $aCRLQueue = [System.Collections.Generic.List[object]]::new()

    $hCertificates = @{}
    $hCheckedCRLs = @{}

    # Issuer names for which a base CRL signature was validated.
    $hValidatedBaseCRLIssuers = @{}

    try {
        # ============================================================
        # 1. CA inventory.
        # ============================================================

        $aAuthorities = @()

        try {
            $aAuthorities = @(
                Get-ADCA -ErrorAction Stop
            )

            $sInventoryStatus = if ($aAuthorities.Count -gt 0) {
                'Healthy'
            }
            else {
                'Warning'
            }

            $aFindings.Add(
                (New-PKIHealthFinding `
                    -Status $sInventoryStatus `
                    -Authority 'Forest' `
                    -Check 'AD CA inventory' `
                    -Details (
                        "$($aAuthorities.Count) CA object(s) discovered."
                    ))
            )
        }
        catch {
            $aFindings.Add(
                (New-PKIHealthFinding `
                    -Status Critical `
                    -Authority 'Forest' `
                    -Check 'AD CA inventory' `
                    -Details (
                        'Could not query CA inventory: ' +
                        $_.Exception.Message
                    ))
            )

            # Continue: PKI certificate objects may still be readable.
        }

        # ============================================================
        # 2. Read PKI objects.
        #
        # CDP objects may be present in this inventory, but their
        # presence alone does not enable a health check.
        # ============================================================

        $aPKIObjects = @(
            Get-PKIADObjects -Type All -ErrorAction Stop
        )

        $aFindings.Add(
            (New-PKIHealthFinding `
                -Status Healthy `
                -Authority 'Forest' `
                -Check 'AD PKI objects' `
                -Details (
                    "$($aPKIObjects.Count) PKI object(s) read. " +
                    'Unreferenced AD CDP publications are not evaluated.'
                ))
        )

        # ============================================================
        # 3. Decode and deduplicate CA certificates.
        # ============================================================

        foreach ($oPKIObject in $aPKIObjects) {
            if (
                -not $oPKIObject.rawData -or
                $oPKIObject.source -notmatch '^(AIA|Root CA)/'
            ) {
                continue
            }

            $oCertificate = $null

            try {
                $oCertificate =
                    [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                        [byte[]]$oPKIObject.rawData
                    )

                $sThumbprint = $oCertificate.Thumbprint

                if ($hCertificates.ContainsKey($sThumbprint)) {
                    $oExistingRecord = $hCertificates[$sThumbprint]

                    if (
                        -not $oExistingRecord.Sources.Contains(
                            [string]$oPKIObject.source
                        )
                    ) {
                        $oExistingRecord.Sources.Add(
                            [string]$oPKIObject.source
                        )
                    }

                    $oCertificate.Dispose()
                    $oCertificate = $null
                }
                else {
                    $aSources =
                        [System.Collections.Generic.List[string]]::new()

                    $aSources.Add(
                        [string]$oPKIObject.source
                    )

                    $oRecord = [PSCustomObject]@{
                        Sources     = $aSources
                        Certificate = $oCertificate
                    }

                    $aCertificates.Add($oRecord)
                    $hCertificates[$sThumbprint] = $oRecord

                    # Ownership transferred to aCertificates.
                    $oCertificate = $null
                }
            }
            catch {
                $aFindings.Add(
                    (New-PKIHealthFinding `
                        -Status Warning `
                        -Authority ([string]$oPKIObject.source) `
                        -Check 'CA certificate decoding' `
                        -Details $_.Exception.Message)
                )
            }
            finally {
                if ($null -ne $oCertificate) {
                    $oCertificate.Dispose()
                }
            }
        }

        if ($aCertificates.Count -eq 0) {
            $aFindings.Add(
                (New-PKIHealthFinding `
                    -Status Critical `
                    -Authority 'Forest' `
                    -Check 'CA certificates in AD' `
                    -Details 'No CA certificate could be decoded.')
            )
        }

        # ============================================================
        # 4. Authority metadata.
        # ============================================================

        foreach ($oAuthority in $aAuthorities) {
            $sCAName = [string]$oAuthority.Name

            $aMatchingCertificates = @(
                $aCertificates |
                    Where-Object {
                        $_.Sources -icontains "AIA/$sCAName" -or
                        $_.Sources -icontains "Root CA/$sCAName" -or
                        $_.Certificate.GetNameInfo(
                            [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
                            $false
                        ) -ieq $sCAName
                    }
            )

            try {
                foreach ($oFinding in (
                    Test-PKIAuthorityMetadata `
                        -Authority $oAuthority `
                        -CertificateRecords $aMatchingCertificates `
                        -ErrorAction Stop
                )) {
                    $aFindings.Add($oFinding)
                }
            }
            catch {
                $aFindings.Add(
                    (New-PKIHealthFinding `
                        -Status Unknown `
                        -Authority $sCAName `
                        -Check 'CA metadata evaluation' `
                        -Details $_.Exception.Message)
                )
            }

            $sHostName = [string]$oAuthority.dNSHostName

            if (-not [string]::IsNullOrWhiteSpace($sHostName)) {
                try {
                    foreach ($sURL in @(
                        Get-PKICARevocationUrls `
                            -ComputerName $sHostName `
                            -CAName $sCAName `
                            -ErrorAction Stop
                    )) {
                        $aCRLQueue.Add(
                            [PSCustomObject]@{
                                URL               = $sURL
                                Type              = 'Base'
                                ExpectedAuthority = $sCAName
                            }
                        )
                    }
                }
                catch {
                    $aFindings.Add(
                        (New-PKIHealthFinding `
                            -Status Unknown `
                            -Authority $sCAName `
                            -Check 'CA CRL distribution points discovery' `
                            -Details $_.Exception.Message)
                    )
                }
            }
        }

        # ============================================================
        # 5. Certificate health and endpoint discovery.
        # ============================================================

        foreach ($oRecord in $aCertificates) {
            $oCertificate = $oRecord.Certificate

            $sAuthority = $oCertificate.GetNameInfo(
                [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
                $false
            )

            if ([System.String]::IsNullOrWhiteSpace($sAuthority)) {
                $sAuthority = $oCertificate.Subject
            }

            try {
                $oCertificateFinding = Test-PKICACertificate `
                    -Certificate $oCertificate `
                    -Authority $sAuthority `
                    -ExpiringWithinDays $ExpiringWithinDays `
                    -ErrorAction Stop

                $aFindings.Add($oCertificateFinding)
            }
            catch {
                $aFindings.Add(
                    (New-PKIHealthFinding `
                        -Status Unknown `
                        -Authority $sAuthority `
                        -Check 'CA certificate evaluation' `
                        -Details $_.Exception.Message)
                )
            }

            # The CDP in this certificate normally concerns its issuer.
            $sExpectedAuthority = $oCertificate.GetNameInfo(
                [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
                $true
            )

            if (
                [System.String]::IsNullOrWhiteSpace(
                    $sExpectedAuthority
                )
            ) {
                $sExpectedAuthority = $oCertificate.Issuer
            }

            try {
                $oURLs = Get-CertificateURL `
                    -Cert $oCertificate `
                    -WarningAction SilentlyContinue `
                    -ErrorAction Stop

                foreach ($sURL in @($oURLs.CDP)) {
                    if (
                        [System.String]::IsNullOrWhiteSpace(
                            [string]$sURL
                        )
                    ) {
                        continue
                    }

                    $aCRLQueue.Add(
                        [PSCustomObject]@{
                            URL = ([string]$sURL).Trim()
                            Type = 'Base'
                            ExpectedAuthority = $sExpectedAuthority
                        }
                    )
                }

                foreach ($sURL in @($oURLs.DeltaCRL)) {
                    if (
                        [System.String]::IsNullOrWhiteSpace(
                            [string]$sURL
                        )
                    ) {
                        continue
                    }

                    $aCRLQueue.Add(
                        [PSCustomObject]@{
                            URL = ([string]$sURL).Trim()
                            Type = 'Delta'
                            ExpectedAuthority = $sExpectedAuthority
                        }
                    )
                }
            }
            catch {
                $aFindings.Add(
                    (New-PKIHealthFinding `
                        -Status Warning `
                        -Authority $sAuthority `
                        -Check 'CRL distribution points discovery' `
                        -Details $_.Exception.Message)
                )
            }
        }

        # ============================================================
        # 6. Referenced endpoint checks.
        #
        # The queue can grow when a validated base CRL exposes
        # Freshest CRL URLs.
        # ============================================================

        for (
            $iCRLIndex = 0;
            $iCRLIndex -lt $aCRLQueue.Count;
            $iCRLIndex++
        ) {
            $oRequest = $aCRLQueue[$iCRLIndex]
            $sURL = [string]$oRequest.URL
            $sKey = "$($oRequest.Type)|$sURL"

            if ($hCheckedCRLs.ContainsKey($sKey)) {
                continue
            }

            $hCheckedCRLs[$sKey] = $true

            $sCheck = if ($oRequest.Type -eq 'Delta') {
                'Delta CRL endpoint'
            }
            else {
                'CRL endpoint'
            }

            Write-Verbose (
                "Checking {0} CRL endpoint: {1}" -f
                $oRequest.Type,
                $sURL
            )

            try {
                $hCRLParameters = @{
                    URL                      = $sURL
                    DownloadTimeout          = $DownloadTimeoutSeconds
                    Certificates             = $aCertificates.ToArray()
                    ExpectedType             = $oRequest.Type
                    WarningRemainingPercent  = $CRLWarningRemainingPercent
                    CriticalRemainingPercent = $CRLCriticalRemainingPercent
                    ErrorAction              = 'Stop'
                }

                $oCRL = Get-CRL @hCRLParameters

                if ($null -eq $oCRL) {
                    throw 'Get-CRL returned no result.'
                }

                $sCRLAuthority = if (
                    -not [System.String]::IsNullOrWhiteSpace(
                        [string]$oCRL.Authority
                    )
                ) {
                    [string]$oCRL.Authority
                }
                else {
                    [string]$oRequest.ExpectedAuthority
                }

                $sStatus = [string]$oCRL.Status
                $sDetails = [string]$oCRL.Details

                if (
                    $oCRL.SignatureStatus -ne 'Valid' -and
                    $sStatus -notin @('Critical', 'Unknown')
                ) {
                    $sStatus = 'Unknown'

                    $sDetails += (
                        ' Signature validation was not successful: ' +
                        "$($oCRL.SignatureStatus)."
                    )
                }

                $aFindings.Add(
                    (New-PKIHealthFinding `
                        -Status $sStatus `
                        -Authority $sCRLAuthority `
                        -Check $sCheck `
                        -Details $sDetails `
                        -URL $sURL `
                        -ThisUpdate $oCRL.ThisUpdate `
                        -NextUpdate $oCRL.NextUpdate `
                        -NextPublish $oCRL.NextPublish `
                        -DaysRemaining $oCRL.DaysRemaining `
                        -SignatureStatus $oCRL.SignatureStatus)
                )

                # ----------------------------------------------------
                # Automatic Delta discovery from a validated base CRL.
                # ----------------------------------------------------

                if (
                    $oRequest.Type -eq 'Base' -and
                    -not $oCRL.IsDelta -and
                    $oCRL.SignatureStatus -eq 'Valid'
                ) {
                    $sIssuerKey = [System.Convert]::ToBase64String(
                        [byte[]]$oCRL.IssuerRawData
                    )

                    $hValidatedBaseCRLIssuers[$sIssuerKey] = $true

                    $aDeltaURLs = @(
                        $oCRL.FreshestCRLUrls |
                            Where-Object {
                                -not [System.String]::IsNullOrWhiteSpace(
                                    [string]$_
                                )
                            }
                    )

                    Write-Verbose (
                        "Validated base CRL '{0}': {1} Freshest CRL URL(s)." -f
                        $sURL,
                        $aDeltaURLs.Count
                    )

                    foreach ($sDeltaURL in $aDeltaURLs) {
                        $sDeltaURL = ([string]$sDeltaURL).Trim()

                        Write-Verbose (
                            "Discovered Delta CRL endpoint: $sDeltaURL"
                        )

                        $aCRLQueue.Add(
                            [PSCustomObject]@{
                                URL               = $sDeltaURL
                                Type              = 'Delta'
                                ExpectedAuthority = $sCRLAuthority
                            }
                        )
                    }
                }
            }
            catch {
                $aFindings.Add(
                    (New-PKIHealthFinding `
                        -Status Critical `
                        -Authority ([string]$oRequest.ExpectedAuthority) `
                        -Check $sCheck `
                        -Details $_.Exception.Message `
                        -URL $sURL)
                )
            }
        }

        # ============================================================
        # 7. Coverage information.
        #
        # Missing discovery is not evidence that a CA is unhealthy.
        # Report it as Unknown, without checking old AD publications.
        # ============================================================

        $hReportedIssuerCoverage = @{}

        foreach ($oRecord in $aCertificates) {
            $oCertificate = $oRecord.Certificate

            $sSubjectKey = [System.Convert]::ToBase64String(
                $oCertificate.SubjectName.RawData
            )

            if ($hReportedIssuerCoverage.ContainsKey($sSubjectKey)) {
                continue
            }

            $hReportedIssuerCoverage[$sSubjectKey] = $true

            if (
                $hValidatedBaseCRLIssuers.ContainsKey(
                    $sSubjectKey
                )
            ) {
                continue
            }

            $sAuthority = $oCertificate.GetNameInfo(
                [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
                $false
            )

            if ([System.String]::IsNullOrWhiteSpace($sAuthority)) {
                $sAuthority = $oCertificate.Subject
            }

            $aFindings.Add(
                (New-PKIHealthFinding `
                    -Status Unknown `
                    -Authority $sAuthority `
                    -Check 'CRL monitoring coverage' `
                    -Details (
                        'No base CRL with a validated signature was ' +
                        'evaluated for this authority. Endpoint discovery ' +
                        'may be incomplete, or a discovered endpoint ' +
                        'could not be validated. Unreferenced AD CDP ' +
                        'objects were not used as a fallback.'
                    ))
            )
        }

        Write-Verbose (
            'CRL endpoints discovered after Freshest CRL processing:'
        )

        foreach ($oRequest in $aCRLQueue) {
            Write-Verbose (
                "Type={0}; URL={1}" -f
                $oRequest.Type,
                $oRequest.URL
            )
        }

        # No additional pass over raw AD CDP objects.
        #
        # Referenced LDAP endpoints have already been checked
        # through Get-CRL, just like HTTP/HTTPS endpoints.
        #
        # Existing but unreferenced AD publications are ignored.
    }
    catch {
        $aFindings.Add(
            (New-PKIHealthFinding `
                -Status Critical `
                -Authority 'Forest' `
                -Check 'PKI health execution' `
                -Details $_.Exception.Message)
        )
    }
    finally {
        foreach ($oRecord in $aCertificates) {
            $oRecord.Certificate.Dispose()
        }
    }

    # ================================================================
    # 8. Overall status.
    # ================================================================

    $iCritical = @(
        $aFindings |
            Where-Object { $_.Status -eq 'Critical' }
    ).Count

    $iUnknown = @(
        $aFindings |
            Where-Object { $_.Status -eq 'Unknown' }
    ).Count

    $iWarning = @(
        $aFindings |
            Where-Object { $_.Status -eq 'Warning' }
    ).Count

    $sOverall = if ($iCritical -gt 0) {
        'Critical'
    }
    elseif ($iUnknown -gt 0) {
        'Unknown'
    }
    elseif ($iWarning -gt 0) {
        'Warning'
    }
    else {
        'Healthy'
    }

    $aFindings.Add(
        (New-PKIHealthFinding `
            -Status $sOverall `
            -Authority 'Forest' `
            -Check 'Overall status' `
            -Details (
                "$iCritical critical, " +
                "$iUnknown unknown, " +
                "$iWarning warning finding(s)."
            ))
    )

    return $aFindings.ToArray()
}