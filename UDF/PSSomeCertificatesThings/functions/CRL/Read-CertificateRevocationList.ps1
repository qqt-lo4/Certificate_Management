function Read-CertificateRevocationList {
    <#
    .SYNOPSIS
        Decodes and validates the metadata and signature of a DER-encoded X.509 CRL.

    .PARAMETER RawData
        DER-encoded CertificateList bytes.

    .PARAMETER IssuerCertificate
        Optional certificate used to match the CRL issuer and verify its signature.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [byte[]]$RawData,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$IssuerCertificate
    )

    if ($RawData.Length -eq 0) { throw 'The CRL data is empty.' }
    $oOuter = Read-DerElement -Data $RawData -Offset 0
    if ($oOuter.Tag -ne 0x30 -or $oOuter.End -ne $RawData.Length) { throw 'Data is not one complete DER CertificateList sequence.' }
    $aOuter = @(Get-DerChildren -Data $RawData -Parent $oOuter)
    if ($aOuter.Count -ne 3 -or $aOuter[0].Tag -ne 0x30 -or $aOuter[1].Tag -ne 0x30 -or $aOuter[2].Tag -ne 0x03) {
        throw 'Malformed CertificateList structure.'
    }

    $aTbs = @(Get-DerChildren -Data $RawData -Parent $aOuter[0])
    $iIndex = 0
    if ($aTbs[$iIndex].Tag -eq 0x02) { $iIndex++ }
    if ($aTbs.Count -lt ($iIndex + 3)) { throw 'Malformed TBSCertList structure.' }
    $oTbsSignature = $aTbs[$iIndex++]
    $oIssuer = $aTbs[$iIndex++]
    $oThisUpdate = $aTbs[$iIndex++]
    if ($oTbsSignature.Tag -ne 0x30 -or $oIssuer.Tag -ne 0x30 -or $oThisUpdate.Tag -notin @(0x17, 0x18)) {
        throw 'Malformed TBSCertList fields.'
    }
    $oNextUpdate = $null
    if (($iIndex -lt $aTbs.Count) -and ($aTbs[$iIndex].Tag -in @(0x17, 0x18))) { $oNextUpdate = $aTbs[$iIndex++] }
    $iRevokedCount = 0
    if (($iIndex -lt $aTbs.Count) -and ($aTbs[$iIndex].Tag -eq 0x30)) {
        $iRevokedCount = @(Get-DerChildren -Data $RawData -Parent $aTbs[$iIndex]).Count
        $iIndex++
    }
    $bIsDeltaCRL = $false
    $aFreshestCRLUrls = [System.Collections.Generic.List[string]]::new()
    if (($iIndex -lt $aTbs.Count) -and ($aTbs[$iIndex].Tag -eq 0xa0)) {
        $aExplicitExtensions = @(Get-DerChildren -Data $RawData -Parent $aTbs[$iIndex])
        foreach ($oExtensionSequence in $aExplicitExtensions) {
            if ($oExtensionSequence.Tag -ne 0x30) { continue }
            foreach ($oExtension in @(Get-DerChildren -Data $RawData -Parent $oExtensionSequence)) {
                if ($oExtension.Tag -ne 0x30) { continue }
                $aExtensionFields = @(Get-DerChildren -Data $RawData -Parent $oExtension)
                if ($aExtensionFields.Count -lt 2) { continue }
                $sExtensionOID = ConvertFrom-DerObjectIdentifier -Data $RawData -Element $aExtensionFields[0]
                if ($sExtensionOID -eq '2.5.29.27') { $bIsDeltaCRL = $true }
                if ($sExtensionOID -eq '2.5.29.46') {
                    $oValue = $aExtensionFields | Where-Object { $_.Tag -eq 0x04 } | Select-Object -Last 1
                    if (-not $oValue -or $oValue.Length -eq 0) { throw 'Freshest CRL extension has no value.' }
                    $aExtensionData = [byte[]]$RawData[$oValue.ContentStart..($oValue.End - 1)]
                    $oExtensionRoot = Read-DerElement -Data $aExtensionData -Offset 0
                    $aPendingElements = [System.Collections.Generic.Stack[object]]::new()
                    $aPendingElements.Push($oExtensionRoot)
                    while ($aPendingElements.Count -gt 0) {
                        $oElement = $aPendingElements.Pop()
                        if ($oElement.Tag -eq 0x86 -and $oElement.Length -gt 0) {
                            $sURL = [System.Text.Encoding]::ASCII.GetString($aExtensionData, $oElement.ContentStart, $oElement.Length)
                            if ($sURL -and -not $aFreshestCRLUrls.Contains($sURL)) { $aFreshestCRLUrls.Add($sURL) }
                        } elseif (($oElement.Tag -band 0x20) -ne 0) {
                            foreach ($oChild in (Get-DerChildren -Data $aExtensionData -Parent $oElement)) { $aPendingElements.Push($oChild) }
                        }
                    }
                }
            }
        }
    }

    $aAlgorithm = @(Get-DerChildren -Data $RawData -Parent $aOuter[1])
    if ($aAlgorithm.Count -lt 1) { throw 'CRL signature algorithm is missing.' }
    $sSignatureAlgorithm = ConvertFrom-DerObjectIdentifier -Data $RawData -Element $aAlgorithm[0]
    $aSignature = [byte[]]$RawData[$aOuter[2].ContentStart..($aOuter[2].End - 1)]
    if ($aSignature.Length -lt 2 -or $aSignature[0] -ne 0) { throw 'Unsupported CRL signature bit string.' }
    $aSignature = [byte[]]$aSignature[1..($aSignature.Length - 1)]
    $oIssuerName = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new([byte[]]$oIssuer.Encoded)
    $oThisUpdateValue = ConvertFrom-DerTime -Data $RawData -Element $oThisUpdate
    $oNextUpdateValue = if ($oNextUpdate) { ConvertFrom-DerTime -Data $RawData -Element $oNextUpdate } else { $null }

    $sSignatureStatus = 'Unknown'
    if ($IssuerCertificate) {
        if (-not [System.Linq.Enumerable]::SequenceEqual([byte[]]$IssuerCertificate.SubjectName.RawData, [byte[]]$oIssuer.Encoded)) {
            $sSignatureStatus = 'IssuerMismatch'
        } else {
            $sHashAlgorithm = switch ($sSignatureAlgorithm) {
                '1.2.840.113549.1.1.5' { [System.Security.Cryptography.HashAlgorithmName]::SHA1 }
                '1.2.840.113549.1.1.11' { [System.Security.Cryptography.HashAlgorithmName]::SHA256 }
                '1.2.840.113549.1.1.12' { [System.Security.Cryptography.HashAlgorithmName]::SHA384 }
                '1.2.840.113549.1.1.13' { [System.Security.Cryptography.HashAlgorithmName]::SHA512 }
                default { $null }
            }
            if ($null -eq $sHashAlgorithm) {
                $sSignatureStatus = 'UnsupportedAlgorithm'
            } else {
                $oRsa = $null
                try {
                    $oRsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($IssuerCertificate)
                    if ($oRsa) {
                        $sSignatureStatus = if ($oRsa.VerifyData($aOuter[0].Encoded, $aSignature, $sHashAlgorithm,
                            [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)) { 'Valid' } else { 'Invalid' }
                    } else {
                        $sSignatureStatus = 'UnsupportedKeyType'
                    }
                } finally {
                    if ($oRsa) { $oRsa.Dispose() }
                }
            }
        }
    }

    [PSCustomObject]@{
        Issuer = $oIssuerName.Name
        IssuerRawData = [byte[]]$oIssuer.Encoded
        ThisUpdate = $oThisUpdateValue
        NextUpdate = $oNextUpdateValue
        RevokedCount = $iRevokedCount
        IsDelta = $bIsDeltaCRL
        FreshestCRLUrls = $aFreshestCRLUrls.ToArray()
        SignatureAlgorithm = $sSignatureAlgorithm
        SignatureStatus = $sSignatureStatus
    }
}
