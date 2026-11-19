function Test-PKIHealth {
    <#
    .SYNOPSIS
        Checks AD CS inventory, CA certificates and published/retrieved CRLs.

    .PARAMETER ExpiringWithinDays
        Warn when a CA certificate or CRL expires within this many days. Default: 30.

    .PARAMETER DownloadTimeoutSeconds
        Timeout per CRL distribution point download. Default: 8 seconds.

    .OUTPUTS
        PSCustomObject[] with Status, Authority, Check, Details, URL, ThisUpdate and NextUpdate.
    #>
    [CmdletBinding()]
    Param(
        [ValidateRange(1, 365)]
        [int]$ExpiringWithinDays = 30,
        [ValidateRange(1, 120)]
        [int]$DownloadTimeoutSeconds = 8
    )

    $aFindings = [System.Collections.Generic.List[object]]::new()
    $dtNowUtc = [DateTime]::UtcNow
    $addFinding = {
        Param($Status, $Authority, $Check, $Details, $URL, $ThisUpdate, $NextUpdate)
        $aFindings.Add([PSCustomObject]@{
            Status = $Status
            Authority = $Authority
            Check = $Check
            Details = $Details
            URL = $URL
            ThisUpdate = $ThisUpdate
            NextUpdate = $NextUpdate
        }) | Out-Null
    }.GetNewClosure()

    $aAuthorities = @()
    try {
        $aAuthorities = @(Get-ADCA)
        & $addFinding 'Healthy' 'Forest' 'AD CA inventory' "$($aAuthorities.Count) CA(s) discovered from AIA and Enrollment Services." $null $null $null
    } catch {
        & $addFinding 'Critical' 'Forest' 'AD CA inventory' "Could not query AD CS objects: $_" $null $null $null
        return $aFindings.ToArray()
    }
    if ($aAuthorities.Count -eq 0) {
        & $addFinding 'Critical' 'Forest' 'AD CA inventory' 'No CA objects were found in Active Directory.' $null $null $null
        return $aFindings.ToArray()
    }

    $aPKIObjects = @()
    try {
        $aPKIObjects = @(Get-PKIADObjects -Type All -ErrorAction Stop)
        & $addFinding 'Healthy' 'Forest' 'AD PKI objects' "$($aPKIObjects.Count) AIA, CDP, Root CA, NTAuth and KRA object(s) read." $null $null $null
    } catch {
        & $addFinding 'Critical' 'Forest' 'AD PKI objects' "Could not read PKI objects from AD: $_" $null $null $null
        return $aFindings.ToArray()
    }

    $aCertificates = [System.Collections.Generic.List[object]]::new()
    foreach ($oPKIObject in $aPKIObjects) {
        if (-not $oPKIObject.rawData -or $oPKIObject.source -notmatch '^(AIA|Root CA)/') { continue }
        try {
            $oCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,[byte[]]$oPKIObject.rawData)
            if (-not ($aCertificates | Where-Object { $_.Certificate.Thumbprint -eq $oCertificate.Thumbprint })) {
                $aCertificates.Add([PSCustomObject]@{ Source = $oPKIObject.source; Certificate = $oCertificate })
            } else {
                $oCertificate.Dispose()
            }
        } catch {
            & $addFinding 'Warning' $oPKIObject.source 'CA certificate decoding' "Could not decode an AD certificate: $_" $null $null $null
        }
    }

    $hActiveADCDPs = @{}
    $hActiveADCDPsByAuthority = @{}
    foreach ($oCertificateRecord in $aCertificates) {
        $sCertificateAuthority = if ($oCertificateRecord.Source -match '^(?:AIA|Root CA)/(.+)$') {
            $Matches[1]
        } else {
            $oCertificateRecord.Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        }
        try {
            $oURLs = Get-CertificateURL -Cert $oCertificateRecord.Certificate -WarningAction SilentlyContinue
            foreach ($sURL in @($oURLs.CDP | Where-Object { $_ })) {
                $sDecodedURL = [Uri]::UnescapeDataString([string]$sURL)
                $oLDAPPath = [regex]::Match($sDecodedURL, '(?i)^ldap:///([^?]+)')
                if (-not $oLDAPPath.Success) { continue }
                $sCDPDN = $oLDAPPath.Groups[1].Value.Trim()
                $hActiveADCDPs[$sCDPDN] = $true
                if (-not $hActiveADCDPsByAuthority.ContainsKey($sCertificateAuthority)) {
                    $hActiveADCDPsByAuthority[$sCertificateAuthority] = @()
                }
                $hActiveADCDPsByAuthority[$sCertificateAuthority] += $sCDPDN
            }
        } catch {
            Write-Verbose "Could not inspect LDAP CDP references on '$sCertificateAuthority': $_"
        }
    }

    $hCheckedCRLs = @{}
    $hCheckedCertificates = @{}
    foreach ($oAuthority in $aAuthorities) {
        $sCAName = [string]$oAuthority.Name
        $sHostName = [string]$oAuthority.dNSHostName
        $aCAcerts = @($aCertificates | Where-Object {
            $_.Source -ieq "AIA/$sCAName" -or $_.Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -ieq $sCAName
        })
        $bOfflineRoot = -not $sHostName -and @($aCAcerts | Where-Object { $_.Certificate.Subject -eq $_.Certificate.Issuer }).Count -gt 0
        if (-not $sHostName) {
            if ($bOfflineRoot) {
                & $addFinding 'NotApplicable' $sCAName 'Enrollment Service hostname' 'Self-signed root CA has no Enrollment Service; this is normal for an offline or out-of-domain root. The managing host cannot be inferred from this AD object.' $null $null $null
            } else {
                & $addFinding 'Critical' $sCAName 'Enrollment Service hostname' 'No DNS hostname is published in Enrollment Services.' $null $null $null
            }
        } else {
            try {
                Resolve-DnsName -Name $sHostName -ErrorAction Stop | Out-Null
                & $addFinding 'Healthy' $sCAName 'DNS resolution' "$sHostName resolves." $null $null $null
            } catch {
                & $addFinding 'Critical' $sCAName 'DNS resolution' "Could not resolve '$sHostName': $_" $null $null $null
            }
        }

        $aTemplates = @($oAuthority.CertificateTemplates | Where-Object { $_ })
        if ($aTemplates.Count -gt 0) {
            & $addFinding 'Healthy' $sCAName 'Published templates' "$($aTemplates.Count) template(s) published." $null $null $null
        } elseif ($bOfflineRoot) {
            & $addFinding 'NotApplicable' $sCAName 'Published templates' 'Templates are not applicable because this self-signed root CA has no Enrollment Service.' $null $null $null
        } else {
            & $addFinding 'Warning' $sCAName 'Published templates' 'No certificate templates are published on this CA.' $null $null $null
        }

        if ($aCAcerts.Count -eq 0) {
            & $addFinding 'Critical' $sCAName 'CA certificate in AD' 'No matching CA certificate was found in the AIA/root certificate objects.' $null $null $null
        }
        foreach ($oCAcertRecord in $aCAcerts) {
            $oCAcert = $oCAcertRecord.Certificate
            if ($oCAcert.Thumbprint) {
                $hCheckedCertificates[$oCAcert.Thumbprint] = $true
            } else {
                & $addFinding 'Warning' $sCAName 'CA certificate thumbprint' 'The decoded CA certificate has no thumbprint.' $null $null $null
            }
            $sCertificateRole = if ($oCAcert.Subject -eq $oCAcert.Issuer) { 'Root CA certificate' } else { 'CA certificate' }
            $dtNotAfterUtc = $oCAcert.NotAfter.ToUniversalTime()
            if ($oCAcert.NotBefore.ToUniversalTime() -gt $dtNowUtc) {
                & $addFinding 'Critical' $sCAName $sCertificateRole "Certificate is not valid until $($oCAcert.NotBefore)." $null $null $null
            } elseif ($dtNotAfterUtc -le $dtNowUtc) {
                & $addFinding 'Critical' $sCAName $sCertificateRole "Certificate expired on $($oCAcert.NotAfter)." $null $null $null
            } elseif ($dtNotAfterUtc -le $dtNowUtc.AddDays($ExpiringWithinDays)) {
                & $addFinding 'Warning' $sCAName $sCertificateRole "Certificate expires on $($oCAcert.NotAfter)." $null $null $null
            } else {
                & $addFinding 'Healthy' $sCAName $sCertificateRole "Certificate is valid until $($oCAcert.NotAfter)." $null $null $null
            }

        }

        $aPublishedCDPs = @($aPKIObjects | Where-Object { $_.source -eq "CDP/$sCAName" })
        if ($aPublishedCDPs.Count -eq 0 -and $hActiveADCDPsByAuthority.ContainsKey($sCAName)) {
            & $addFinding 'Critical' $sCAName 'CRL publication in AD' 'The CA certificate references an LDAP CDP, but no matching CDP object was found in AD.' $null $null $null
        } elseif ($aPublishedCDPs.Count -eq 0) {
            if ($bOfflineRoot) {
                & $addFinding 'NotApplicable' $sCAName 'CRL publication in AD' 'No AD CDP object exists for this offline root. Its CDP URL is checked separately when present in the root certificate.' $null $null $null
            } else {
                & $addFinding 'NotApplicable' $sCAName 'CRL publication in AD' 'No LDAP CDP reference was found in the CA certificates; AD publication is not configured for this CA.' $null $null $null
            }
        }
    }

    foreach ($oCertificateRecord in $aCertificates) {
        $oCertificate = $oCertificateRecord.Certificate
        $sAuthority = $oCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        if (-not $hCheckedCertificates.ContainsKey($oCertificate.Thumbprint)) {
            $hCheckedCertificates[$oCertificate.Thumbprint] = $true
            $dtNotAfterUtc = $oCertificate.NotAfter.ToUniversalTime()
            if ($dtNotAfterUtc -le $dtNowUtc) {
                & $addFinding 'Critical' $sAuthority 'Root/standalone CA certificate' "Certificate expired on $($oCertificate.NotAfter)." $null $null $null
            } elseif ($dtNotAfterUtc -le $dtNowUtc.AddDays($ExpiringWithinDays)) {
                & $addFinding 'Warning' $sAuthority 'Root/standalone CA certificate' "Certificate expires on $($oCertificate.NotAfter)." $null $null $null
            } else {
                & $addFinding 'Healthy' $sAuthority 'Root/standalone CA certificate' "Certificate is valid until $($oCertificate.NotAfter)." $null $null $null
            }
        }

        try {
            $oURLs = Get-CertificateURL -Cert $oCertificate -WarningAction SilentlyContinue
            foreach ($sURL in @($oURLs.CDP | Where-Object { $_ } | Sort-Object -Unique)) {
                if ($hCheckedCRLs.ContainsKey($sURL)) { continue }
                $hCheckedCRLs[$sURL] = $true
                try {
                    $aRawCRL = Get-CRL -URL $sURL -DownloadTimeout $DownloadTimeoutSeconds -ReturnRawData -ErrorAction Stop
                    if ($aRawCRL -isnot [byte[]]) { throw "The CRL endpoint did not return DER bytes: $aRawCRL" }
                    $oCRL = Read-CertificateRevocationList -RawData $aRawCRL
                    $oCRLIssuer = $aCertificates | Where-Object {
                        [System.Linq.Enumerable]::SequenceEqual([byte[]]$_.Certificate.SubjectName.RawData, [byte[]]$oCRL.IssuerRawData)
                    } | Select-Object -First 1
                    $oCRLHealth = if ($oCRLIssuer) {
                        Test-CertificateRevocationList -RawData $aRawCRL -IssuerCertificate $oCRLIssuer.Certificate -ExpiringWithinDays $ExpiringWithinDays
                    } else {
                        Test-CertificateRevocationList -RawData $aRawCRL -ExpiringWithinDays $ExpiringWithinDays
                    }
                    & $addFinding $oCRLHealth.Status $sAuthority 'CRL endpoint' $oCRLHealth.Details $sURL $oCRLHealth.ThisUpdate $oCRLHealth.NextUpdate
                } catch {
                    & $addFinding 'Critical' $sAuthority 'CRL endpoint' "Could not download or decode CRL: $_" $sURL $null $null
                }
            }
        } catch {
            & $addFinding 'Warning' $sAuthority 'CRL distribution points' "Could not read CDP URLs: $_" $null $null $null
        }
    }

    foreach ($oPublishedCDP in @($aPKIObjects | Where-Object { $_.source -like 'CDP/*' })) {
        $sAuthority = [string]$oPublishedCDP.issuer
        $sPublishedCDPDN = [string]$oPublishedCDP.distinguishedName
        if (-not $sPublishedCDPDN -or -not $hActiveADCDPs.ContainsKey($sPublishedCDPDN)) {
            & $addFinding 'NotApplicable' $sAuthority 'Unreferenced AD CDP object' "AD CDP '$($oPublishedCDP.subject)' is present but is not referenced by any CA certificate CDP; it may be a stale publication." $null $null $null
            continue
        }
        foreach ($sCRLProperty in @('CRLData', 'DeltaCRLData')) {
            $aPublishedCRLs = @()
            foreach ($oBlob in @($oPublishedCDP.$sCRLProperty)) {
                if ($oBlob -is [byte[]] -and $oBlob.Length -gt 0) { $aPublishedCRLs += ,$oBlob }
            }
            if ($aPublishedCRLs.Count -eq 0) {
                if ($sCRLProperty -eq 'CRLData') {
                    & $addFinding 'Critical' $sAuthority 'CRL publication in AD' "CDP '$($oPublishedCDP.subject)' has no base CRL data." $null $null $null
                }
                continue
            }
            foreach ($aRawCRL in $aPublishedCRLs) {
                try {
                    $oCRL = Read-CertificateRevocationList -RawData $aRawCRL
                    $oCRLIssuer = $aCertificates | Where-Object {
                        [System.Linq.Enumerable]::SequenceEqual([byte[]]$_.Certificate.SubjectName.RawData, [byte[]]$oCRL.IssuerRawData)
                    } | Select-Object -First 1
                    $oCRLHealth = if ($oCRLIssuer) {
                        Test-CertificateRevocationList -RawData $aRawCRL -IssuerCertificate $oCRLIssuer.Certificate -ExpiringWithinDays $ExpiringWithinDays
                    } else {
                        Test-CertificateRevocationList -RawData $aRawCRL -ExpiringWithinDays $ExpiringWithinDays
                    }
                    $sCheck = if ($sCRLProperty -eq 'DeltaCRLData') { 'Delta CRL publication in AD' } else { 'CRL publication in AD' }
                    $sDetails = "AD CDP '$($oPublishedCDP.subject)'. $($oCRLHealth.Details)"
                    & $addFinding $oCRLHealth.Status $sAuthority $sCheck $sDetails $null $oCRLHealth.ThisUpdate $oCRLHealth.NextUpdate
                } catch {
                    & $addFinding 'Critical' $sAuthority 'CRL publication in AD' "Published CRL '$($oPublishedCDP.subject)' could not be decoded: $_" $null $null $null
                }
            }
        }
    }

    $aOverall = @($aFindings | Where-Object Status -eq 'Critical')
    $sOverall = if ($aOverall.Count -gt 0) { 'Critical' } elseif (@($aFindings | Where-Object Status -eq 'Warning').Count -gt 0) { 'Warning' } elseif (@($aFindings | Where-Object Status -eq 'Unknown').Count -gt 0) { 'Unknown' } else { 'Healthy' }
    & $addFinding $sOverall 'Forest' 'Overall status' "$(@($aFindings | Where-Object Status -eq 'Critical').Count) critical, $(@($aFindings | Where-Object Status -eq 'Warning').Count) warning finding(s)." $null $null $null

    foreach ($oCertificateRecord in $aCertificates) { $oCertificateRecord.Certificate.Dispose() }
    return $aFindings.ToArray()
}
