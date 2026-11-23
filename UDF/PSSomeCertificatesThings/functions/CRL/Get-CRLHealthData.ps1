function Get-CRLHealthData {
    <#
    .SYNOPSIS
        Parses CRL bytes and evaluates their health.

    .DESCRIPTION
        Shared processing for downloaded CRLs and CRLs read from AD.

        Performs:
            - CRL decoding
            - issuer certificate lookup
            - evaluation using matching issuer certificates
            - consolidation of parsed data and health results

        Does not:
            - download CRLs
            - query Active Directory
            - create PKI findings
            - dispose supplied certificates

        Dependencies:
            Read-CertificateRevocationList
            Test-CertificateRevocationList

    .PARAMETER RawData
        DER-encoded CRL bytes.

    .PARAMETER Certificates
        Issuer certificate candidates.

        Accepts X509Certificate2 objects or objects containing
        a Certificate property holding an X509Certificate2.

    .PARAMETER ExpectedType
        Expected CRL type.
        Auto uses the decoded CRL type.

    .PARAMETER WarningRemainingPercent
        Forwarded to Test-CertificateRevocationList.

    .PARAMETER CriticalRemainingPercent
        Forwarded to Test-CertificateRevocationList.

    .OUTPUTS
        PSCustomObject containing parsed data and health information.

    .NOTES
        NextPublish is populated only if the existing decoder exposes it.

        This function does not implement a separate NextPublish decoder
        or change the existing health evaluation policy.
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [byte[]]$RawData,

        [AllowEmptyCollection()]
        [object[]]$Certificates = @(),

        [ValidateSet('Auto', 'Base', 'Delta')]
        [string]$ExpectedType = 'Auto',

        [ValidateRange(1, 99)]
        [int]$WarningRemainingPercent = 5,

        [ValidateRange(0, 98)]
        [int]$CriticalRemainingPercent = 2
    )

    if ($CriticalRemainingPercent -ge $WarningRemainingPercent) {
        throw (
            'CriticalRemainingPercent must be lower than ' +
            'WarningRemainingPercent.'
        )
    }

    # ------------------------------------------------------------
    # 1. Decode the CRL.
    # ------------------------------------------------------------

    $oCRL = Read-CertificateRevocationList `
        -RawData $RawData `
        -ErrorAction Stop

    if ($null -eq $oCRL) {
        throw 'CRL parsing returned no result.'
    }

    $sActualType = if ($oCRL.IsDelta) {
        'Delta'
    }
    else {
        'Base'
    }

    $sExpectedType = if ($ExpectedType -eq 'Auto') {
        $sActualType
    }
    else {
        $ExpectedType
    }

    # ------------------------------------------------------------
    # 2. Find matching issuer certificates.
    # ------------------------------------------------------------

    $sIssuerKey = [System.Convert]::ToBase64String(
        [byte[]]$oCRL.IssuerRawData
    )

    $hSeenCertificates = @{}

    $aIssuerCandidates = @(
        foreach ($oItem in $Certificates) {
            $oCertificate = $null

            if (
                $oItem -is
                [System.Security.Cryptography.X509Certificates.X509Certificate2]
            ) {
                $oCertificate = $oItem
            }
            elseif (
                $null -ne $oItem -and
                $null -ne $oItem.PSObject.Properties['Certificate']
            ) {
                $oCertificate = $oItem.Certificate
            }

            if (
                $oCertificate -isnot
                [System.Security.Cryptography.X509Certificates.X509Certificate2]
            ) {
                continue
            }

            $sSubjectKey = [System.Convert]::ToBase64String(
                $oCertificate.SubjectName.RawData
            )

            if ($sSubjectKey -cne $sIssuerKey) {
                continue
            }

            if ($hSeenCertificates.ContainsKey($oCertificate.Thumbprint)) {
                continue
            }

            $hSeenCertificates[$oCertificate.Thumbprint] = $true

            $oCertificate
        }
    )

    # ------------------------------------------------------------
    # 3. Evaluate the CRL.
    #
    # Several CA certificates may have the same subject after renewal.
    # Try each candidate until a valid signature is found.
    # ------------------------------------------------------------

    $hHealthParameters = @{
        RawData                  = $RawData
        ExpectedType             = $sExpectedType
        WarningRemainingPercent  = $WarningRemainingPercent
        CriticalRemainingPercent = $CriticalRemainingPercent
        ErrorAction              = 'Stop'
    }

    $oHealth = $null
    $oIssuerCertificate = $null

    $aEvaluationErrors =
        [System.Collections.Generic.List[string]]::new()

    if ($aIssuerCandidates.Count -eq 0) {
        $oHealth = Test-CertificateRevocationList @hHealthParameters
    }
    else {
        foreach ($oCandidate in $aIssuerCandidates) {
            try {
                $oCandidateHealth = Test-CertificateRevocationList `
                    @hHealthParameters `
                    -IssuerCertificate $oCandidate

                if ($null -eq $oCandidateHealth) {
                    throw 'CRL health function returned no result.'
                }

                # Keep the first completed evaluation as a fallback.
                if ($null -eq $oHealth) {
                    $oHealth = $oCandidateHealth
                    $oIssuerCertificate = $oCandidate
                }

                if ($oCandidateHealth.SignatureStatus -eq 'Valid') {
                    $oHealth = $oCandidateHealth
                    $oIssuerCertificate = $oCandidate
                    break
                }
            }
            catch {
                $aEvaluationErrors.Add(
                    "$($oCandidate.Thumbprint): $($_.Exception.Message)"
                )
            }
        }

        if ($null -eq $oHealth) {
            throw (
                'CRL evaluation failed for all issuer candidates: ' +
                ($aEvaluationErrors -join ' | ')
            )
        }
    }

    if ($null -eq $oHealth) {
        throw 'CRL health function returned no result.'
    }

    # ------------------------------------------------------------
    # 4. Normalize useful properties.
    # ------------------------------------------------------------

    $sAuthority = if ($oIssuerCertificate) {
        $oIssuerCertificate.GetNameInfo(
            [System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName,
            $false
        )
    }
    else {
        [string]$oCRL.Issuer
    }

    if ([string]::IsNullOrWhiteSpace($sAuthority)) {
        $sAuthority = 'Unknown issuer'
    }

    $dtThisUpdate = ([datetime]$oCRL.ThisUpdate).ToUniversalTime()

    $dtNextUpdate = if ($null -ne $oCRL.NextUpdate) {
        ([datetime]$oCRL.NextUpdate).ToUniversalTime()
    }
    else {
        $null
    }

    $dtNextPublish = $null

    if (
        $null -ne $oCRL.PSObject.Properties['NextPublish'] -and
        $null -ne $oCRL.NextPublish
    ) {
        $dtNextPublish = ([datetime]$oCRL.NextPublish).ToUniversalTime()
    }

    $iDaysRemaining = if ($null -ne $dtNextUpdate) {
        [int][System.Math]::Floor(
            ($dtNextUpdate - [DateTime]::UtcNow).TotalDays
        )
    }
    else {
        $null
    }

    # ------------------------------------------------------------
    # 5. Return data, not a finding or SolarWinds output.
    # ------------------------------------------------------------

    [PSCustomObject]@{
        Type              = $sActualType
        IsDelta           = [bool]$oCRL.IsDelta

        Authority         = $sAuthority
        Issuer            = $oCRL.Issuer
        IssuerRawData     = $oCRL.IssuerRawData
        IssuerCertificate = $oIssuerCertificate

        ThisUpdate        = $dtThisUpdate
        NextUpdate        = $dtNextUpdate
        NextPublish       = $dtNextPublish
        DaysRemaining     = $iDaysRemaining

        FreshestCRLUrls   = @(
            $oCRL.FreshestCRLUrls |
                Where-Object { $_ }
        )

        Status            = $oHealth.Status
        Details           = $oHealth.Details
        SignatureStatus   = $oHealth.SignatureStatus

        EvaluationErrors  = $aEvaluationErrors.ToArray()

        ParsedCRL         = $oCRL
        Health            = $oHealth
        RawData           = $RawData
    }
}