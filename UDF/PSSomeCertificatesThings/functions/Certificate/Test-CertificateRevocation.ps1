function Test-CertificateRevocation {
    <#
    .SYNOPSIS
        Checks the revocation status of an X.509 certificate using the Windows chain engine.

    .DESCRIPTION
        Performs an online revocation check for the end certificate using the CRL/OCSP
        locations published by the certificate. An unavailable responder is reported as
        Unknown, never as Good or Revoked.

    .PARAMETER Certificate
        Certificate to check.

    .PARAMETER TimeoutSeconds
        Maximum URL retrieval timeout configured on the chain policy. Default: 5 seconds.

    .OUTPUTS
        PSCustomObject with Status (Good, Revoked, or Unknown) and Details.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [ValidateRange(1, 120)]
        [int]$TimeoutSeconds = 5
    )

    Process {
        $oChain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        try {
            $oChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
            $oChain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EndCertificateOnly
            $oChain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
            $oChain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::AllowUnknownCertificateAuthority

            $bChainBuilt = $oChain.Build($Certificate)
            if ($oChain.ChainElements.Count -eq 0) {
                return [PSCustomObject]@{ Status = 'Unknown'; Details = 'Certificate chain could not be built.' }
            }

            $aLeafStatuses = @($oChain.ChainElements[0].ChainElementStatus)
            if ($aLeafStatuses | Where-Object { $_.Status -band [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::Revoked }) {
                return [PSCustomObject]@{ Status = 'Revoked'; Details = 'The certificate is listed as revoked.' }
            }

            $aUnknownStatuses = @($aLeafStatuses | Where-Object {
                $_.Status -band ([System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::RevocationStatusUnknown -bor
                    [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::OfflineRevocation)
            })
            if ($aUnknownStatuses.Count -gt 0) {
                $sDetails = ($aUnknownStatuses | ForEach-Object { $_.StatusInformation.Trim() } | Where-Object { $_ }) -join ' '
                return [PSCustomObject]@{ Status = 'Unknown'; Details = $sDetails }
            }

            $aChainStatuses = @($oChain.ChainStatus | Where-Object {
                $_.Status -ne [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError
            })
            if (-not $bChainBuilt -or $aChainStatuses.Count -gt 0) {
                $sDetails = ($aChainStatuses | ForEach-Object { $_.StatusInformation.Trim() } | Where-Object { $_ }) -join ' '
                if (-not $sDetails) { $sDetails = 'Certificate chain validation was inconclusive.' }
                return [PSCustomObject]@{ Status = 'Unknown'; Details = $sDetails }
            }

            return [PSCustomObject]@{ Status = 'Good'; Details = 'Online revocation check passed.' }
        } catch {
            return [PSCustomObject]@{ Status = 'Unknown'; Details = $_.Exception.Message }
        } finally {
            $oChain.Dispose()
        }
    }
}