function Test-CertificateRevocationList {
    <#
    .SYNOPSIS
        Evaluates the freshness and signature status of a DER-encoded CRL.

    .PARAMETER ExpiringWithinDays
        Absolute-day mode: report Warning when an unexpired CRL expires within this many days.

    .PARAMETER WarningRemainingPercent
        Percentage mode: report Warning when this percentage or less of the CRL validity interval remains.

    .PARAMETER CriticalRemainingPercent
        Percentage mode: report Critical when this percentage or less of the CRL validity interval remains.
    #>
    [CmdletBinding(DefaultParameterSetName = 'RemainingPercent')]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [byte[]]$RawData,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$IssuerCertificate,
        [Parameter(Mandatory, ParameterSetName = 'ExpiringWithinDays')]
        [ValidateRange(1, 365)]
        [int]$ExpiringWithinDays,
        [Parameter(ParameterSetName = 'RemainingPercent')]
        [ValidateRange(1, 99)]
        [int]$WarningRemainingPercent = 25,
        [Parameter(ParameterSetName = 'RemainingPercent')]
        [ValidateRange(0, 98)]
        [int]$CriticalRemainingPercent = 15,
        [ValidateSet('Any', 'Base', 'Delta')]
        [string]$ExpectedType = 'Any'
    )

    $bUseRemainingPercent = $PSCmdlet.ParameterSetName -eq 'RemainingPercent'
    if ($bUseRemainingPercent -and $CriticalRemainingPercent -ge $WarningRemainingPercent) {
        throw 'CriticalRemainingPercent must be lower than WarningRemainingPercent.'
    }
    $oCRL = if ($IssuerCertificate) {
        Read-CertificateRevocationList -RawData $RawData -IssuerCertificate $IssuerCertificate
    } else {
        Read-CertificateRevocationList -RawData $RawData
    }
    $dtNowUtc = [DateTime]::UtcNow
    $sStatus = 'Healthy'
    $aDetails = [System.Collections.Generic.List[string]]::new()
    $aDetails.Add("Issuer $($oCRL.Issuer); $($oCRL.RevokedCount) revoked entry(ies).")
    if ($ExpectedType -eq 'Delta' -and -not $oCRL.IsDelta) {
        $sStatus = 'Critical'
        $aDetails.Add('A delta CRL was expected, but the downloaded list is a base CRL.')
    } elseif ($ExpectedType -eq 'Base' -and $oCRL.IsDelta) {
        $sStatus = 'Critical'
        $aDetails.Add('A base CRL was expected, but the downloaded list is a delta CRL.')
    }

    if ($null -eq $oCRL.NextUpdate) {
        if ($sStatus -ne 'Critical') { $sStatus = 'Warning' }
        $aDetails.Add('No NextUpdate is present.')
    } elseif ($oCRL.NextUpdate -le $dtNowUtc) {
        $sStatus = 'Critical'
        $aDetails.Add("CRL expired at $($oCRL.NextUpdate.ToLocalTime()).")
    } else {
        $tsValidity = $oCRL.NextUpdate - $oCRL.ThisUpdate
        if ($tsValidity.TotalSeconds -le 0) {
            $sStatus = 'Critical'
            $aDetails.Add('CRL validity interval is invalid.')
        } elseif (-not $bUseRemainingPercent) {
            $iDaysRemaining = ($oCRL.NextUpdate - $dtNowUtc).TotalDays
            $aDetails.Add(("{0:N1} day(s) remain (warning <= {1} days)." -f $iDaysRemaining, $ExpiringWithinDays))
            if ($iDaysRemaining -le $ExpiringWithinDays -and $sStatus -ne 'Critical') {
                $sStatus = 'Warning'
                $aDetails.Add("CRL expires at $($oCRL.NextUpdate.ToLocalTime()).")
            }
        } else {
            $iRemainingPercent = 100 * (($oCRL.NextUpdate - $dtNowUtc).TotalSeconds / $tsValidity.TotalSeconds)
            $aDetails.Add(("{0:N1}% of the CRL validity period remains (warning <= {1}%, critical <= {2}%)." -f $iRemainingPercent, $WarningRemainingPercent, $CriticalRemainingPercent))
            if ($iRemainingPercent -le $CriticalRemainingPercent) {
                $sStatus = 'Critical'
                $aDetails.Add("CRL expires at $($oCRL.NextUpdate.ToLocalTime()).")
            } elseif ($iRemainingPercent -le $WarningRemainingPercent -and $sStatus -ne 'Critical') {
                $sStatus = 'Warning'
                $aDetails.Add("CRL expires at $($oCRL.NextUpdate.ToLocalTime()).")
            }
        }
    }
    if ($oCRL.ThisUpdate -gt $dtNowUtc.AddMinutes(5)) {
        if ($sStatus -ne 'Critical') { $sStatus = 'Warning' }
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
        IsDelta = $oCRL.IsDelta
        RemainingPercent = if ($oCRL.NextUpdate -and $oCRL.ThisUpdate -lt $oCRL.NextUpdate) { 100 * (($oCRL.NextUpdate - $dtNowUtc).TotalSeconds / ($oCRL.NextUpdate - $oCRL.ThisUpdate).TotalSeconds) } else { $null }
        SignatureStatus = $oCRL.SignatureStatus
    }
}
