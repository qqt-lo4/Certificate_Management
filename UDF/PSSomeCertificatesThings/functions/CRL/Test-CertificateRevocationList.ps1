function Test-CertificateRevocationList {
    <#
    .SYNOPSIS
        Evaluates the freshness and signature status of a DER-encoded CRL.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [byte[]]$RawData,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$IssuerCertificate,
        [ValidateRange(1, 365)]
        [int]$ExpiringWithinDays = 30
    )

    $oCRL = if ($IssuerCertificate) {
        Read-CertificateRevocationList -RawData $RawData -IssuerCertificate $IssuerCertificate
    } else {
        Read-CertificateRevocationList -RawData $RawData
    }
    $dtNowUtc = [DateTime]::UtcNow
    $sStatus = 'Healthy'
    $aDetails = [System.Collections.Generic.List[string]]::new()
    $aDetails.Add("Issuer $($oCRL.Issuer); $($oCRL.RevokedCount) revoked entry(ies).")

    if ($null -eq $oCRL.NextUpdate) {
        $sStatus = 'Warning'
        $aDetails.Add('No NextUpdate is present.')
    } elseif ($oCRL.NextUpdate -le $dtNowUtc) {
        $sStatus = 'Critical'
        $aDetails.Add("CRL expired at $($oCRL.NextUpdate.ToLocalTime()).")
    } elseif ($oCRL.NextUpdate -le $dtNowUtc.AddDays($ExpiringWithinDays)) {
        $sStatus = 'Warning'
        $aDetails.Add("CRL expires at $($oCRL.NextUpdate.ToLocalTime()).")
    }
    if ($oCRL.ThisUpdate -gt $dtNowUtc.AddMinutes(5)) {
        $sStatus = 'Warning'
        $aDetails.Add("ThisUpdate is in the future ($($oCRL.ThisUpdate)).")
    }

    switch ($oCRL.SignatureStatus) {
        'Invalid' { $sStatus = 'Critical'; $aDetails.Add('CRL signature is invalid.') }
        'IssuerMismatch' { $sStatus = 'Critical'; $aDetails.Add('CRL issuer does not match the signing certificate.') }
        'UnsupportedAlgorithm' { if ($sStatus -eq 'Healthy') { $sStatus = 'Warning' }; $aDetails.Add('Signature algorithm is unsupported for verification.') }
        'UnsupportedKeyType' { if ($sStatus -eq 'Healthy') { $sStatus = 'Warning' }; $aDetails.Add('Issuer key type is unsupported for verification.') }
        'Unknown' { if ($sStatus -eq 'Healthy') { $sStatus = 'Warning' }; $aDetails.Add('Issuer certificate was not found; signature was not verified.') }
    }

    [PSCustomObject]@{
        Status = $sStatus
        Details = ($aDetails -join ' ')
        Issuer = $oCRL.Issuer
        ThisUpdate = $oCRL.ThisUpdate
        NextUpdate = $oCRL.NextUpdate
        RevokedCount = $oCRL.RevokedCount
        SignatureStatus = $oCRL.SignatureStatus
    }
}
