function Test-PKIADCRL {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [byte[]]$RawData,

        [Parameter(Mandatory)]
        [ValidateSet('Base', 'Delta')]
        [string]$ExpectedType,

        [Parameter(Mandatory)]
        [string]$Source,

        [AllowEmptyCollection()]
        [object[]]$CertificateRecords = @(),

        [ValidateRange(1, 99)]
        [int]$WarningRemainingPercent = 5,

        [ValidateRange(0, 98)]
        [int]$CriticalRemainingPercent = 2
    )

    $sCheck = if ($ExpectedType -eq 'Delta') {
        'Delta CRL publication in AD'
    }
    else {
        'CRL publication in AD'
    }

    $sAuthority = 'Unknown issuer'

    try {
        $oCRLData = Get-CRLHealthData `
            -RawData $RawData `
            -Certificates $CertificateRecords `
            -ExpectedType $ExpectedType `
            -WarningRemainingPercent $WarningRemainingPercent `
            -CriticalRemainingPercent $CriticalRemainingPercent `
            -ErrorAction Stop

        $sAuthority = $oCRLData.Authority
        $sStatus = [string]$oCRLData.Status
        $sDetails = "$Source. $($oCRLData.Details)"

        # Preserve the existing safeguard:
        # no Healthy result without successful signature validation.
        if (
            $oCRLData.SignatureStatus -ne 'Valid' -and
            $sStatus -notin @('Critical', 'Unknown')
        ) {
            $sStatus = 'Unknown'

            $sDetails += (
                ' Signature validation was not successful: ' +
                "$($oCRLData.SignatureStatus)."
            )
        }

        New-PKIHealthFinding `
            -Status $sStatus `
            -Authority $sAuthority `
            -Check $sCheck `
            -Details $sDetails `
            -ThisUpdate $oCRLData.ThisUpdate `
            -NextUpdate $oCRLData.NextUpdate `
            -NextPublish $oCRLData.NextPublish `
            -DaysRemaining $oCRLData.DaysRemaining `
            -SignatureStatus $oCRLData.SignatureStatus
    }
    catch {
        New-PKIHealthFinding `
            -Status Critical `
            -Authority $sAuthority `
            -Check $sCheck `
            -Details "$Source. $($_.Exception.Message)"
    }
}