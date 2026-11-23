function Test-PKICACertificate {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]
        $Certificate,

        [Parameter(Mandatory)]
        [string]$Authority,

        [ValidateRange(1, 365)]
        [int]$ExpiringWithinDays = 30
    )

    $dtNowUtc = [DateTime]::UtcNow
    $dtNotBeforeUtc = $Certificate.NotBefore.ToUniversalTime()
    $dtNotAfterUtc = $Certificate.NotAfter.ToUniversalTime()

    $bSelfIssued = (
        [System.Convert]::ToBase64String(
            $Certificate.SubjectName.RawData
        ) -ceq
        [System.Convert]::ToBase64String(
            $Certificate.IssuerName.RawData
        )
    )

    $sCheck = if ($bSelfIssued) {
        'Root CA certificate'
    }
    else {
        'CA certificate'
    }

    $iDaysRemaining = [int][System.Math]::Floor(
        ($dtNotAfterUtc - $dtNowUtc).TotalDays
    )

    $bIsCA = $false

    foreach ($oExtension in $Certificate.Extensions) {
        if ($oExtension.Oid.Value -eq '2.5.29.19') {
            $oConstraints =
                [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new()

            $oConstraints.CopyFrom($oExtension)
            $bIsCA = $oConstraints.CertificateAuthority
            break
        }
    }

    if (-not $bIsCA) {
        $sStatus = 'Critical'
        $sDetails = 'Certificate is not marked as a CA certificate.'
    }
    elseif ($dtNotAfterUtc -le $dtNotBeforeUtc) {
        $sStatus = 'Critical'
        $sDetails = 'Certificate validity interval is invalid.'
    }
    elseif ($dtNotBeforeUtc -gt $dtNowUtc) {
        $sStatus = 'Critical'
        $sDetails = (
            "Certificate is not valid until " +
            "$($dtNotBeforeUtc.ToString('u'))."
        )
    }
    elseif ($dtNotAfterUtc -le $dtNowUtc) {
        $sStatus = 'Critical'
        $sDetails = (
            "Certificate expired on " +
            "$($dtNotAfterUtc.ToString('u'))."
        )
    }
    elseif ($dtNotAfterUtc -le $dtNowUtc.AddDays($ExpiringWithinDays)) {
        $sStatus = 'Warning'
        $sDetails = (
            "Certificate expires on " +
            "$($dtNotAfterUtc.ToString('u'))."
        )
    }
    else {
        $sStatus = 'Healthy'
        $sDetails = (
            "Certificate is valid until " +
            "$($dtNotAfterUtc.ToString('u'))."
        )
    }

    New-PKIHealthFinding `
        -Status $sStatus `
        -Authority $Authority `
        -Check $sCheck `
        -Details (
            "$sDetails Thumbprint: $($Certificate.Thumbprint). " +
            "Days remaining: $iDaysRemaining."
        ) `
        -ThisUpdate $dtNotBeforeUtc `
        -NextUpdate $dtNotAfterUtc `
        -DaysRemaining $iDaysRemaining
}