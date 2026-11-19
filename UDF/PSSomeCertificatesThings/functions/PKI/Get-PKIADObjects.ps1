function Get-PKIADObjects {
    <#
    .SYNOPSIS
        Retrieves all PKI-related objects from Active Directory Public Key Services.

    .DESCRIPTION
        Queries AD Configuration partition for PKI objects: AIA (intermediate CA certs),
        CDP (CRL distribution points), NTAuthCertificates (CAs trusted for client auth),
        KRA (Key Recovery Agents), and Root CAs.

        Binary certificates (cACertificate, userCertificate) are decoded into readable
        properties (subject, issuer, validity, algorithm, thumbprint).

    .PARAMETER Type
        The type of PKI objects to retrieve. If not specified, returns all types.

    .OUTPUTS
        [PSCustomObject[]] PKI objects with decoded certificate information.

    .EXAMPLE
        Get-PKIADObjects

    .EXAMPLE
        Get-PKIADObjects -Type AIA

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        History :
            1.0.0 - 2026-03-30 - Initial version
    #>
    [CmdletBinding()]
    Param(
        [ValidateSet('AIA', 'CDP', 'NTAuth', 'KRA', 'RootCA', 'All')]
        [string]$Type = 'All'
    )

    Process {
        $sForestName = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name
        $oForest = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$sForestName")
        $sForestDN = $oForest.distinguishedName
        $sPKSBase = "CN=Public Key Services,CN=Services,CN=Configuration,$sForestDN"

        $aAllResults = @()

        # --- AIA: Intermediate CA certificates ---
        if ($Type -in @('All', 'AIA')) {
            Write-Verbose "Querying AIA..."
            $aAIA = Get-PKIContainerCertificates -ContainerDN "LDAP://$sForestName/CN=AIA,$sPKSBase" -SourceLabel 'AIA'
            $aAllResults += $aAIA
        }

        # --- NTAuthCertificates: CAs trusted for client authentication ---
        if ($Type -in @('All', 'NTAuth')) {
            Write-Verbose "Querying NTAuthCertificates..."
            $sDN = "LDAP://$sForestName/CN=NTAuthCertificates,$sPKSBase"
            try {
                $oEntry = [ADSI]$sDN
                $aCertBytes = $oEntry.Properties['cACertificate']
                if ($aCertBytes) {
                    foreach ($certData in $aCertBytes) {
                        $oCertInfo = ConvertFrom-BinaryCertificate -Bytes ([byte[]]$certData) -Source 'NTAuthCertificates'
                        if ($oCertInfo) { $aAllResults += $oCertInfo }
                    }
                }
            } catch {
                Write-Verbose "Failed to query NTAuthCertificates: $_"
            }
        }

        # --- Root CAs ---
        if ($Type -in @('All', 'RootCA')) {
            Write-Verbose "Querying Root CAs from AD..."
            $aRootCAs = Get-PKIContainerCertificates -ContainerDN "LDAP://$sForestName/CN=Certification Authorities,$sPKSBase" -SourceLabel 'Root CA'
            $aAllResults += $aRootCAs

            # Si aucune Root CA dans AD, chercher dans le magasin local
            # en se basant sur les émetteurs des certificats AIA
            if ($aRootCAs.Count -eq 0) {
                Write-Verbose "No Root CAs in AD, searching local certificate store..."
                # Collecter les AIA si pas encore fait, pour connaître les issuers
                $aAIACerts = if ($aAllResults | Where-Object { $_.source -like 'AIA/*' }) {
                    $aAllResults | Where-Object { $_.source -like 'AIA/*' }
                } else {
                    Get-PKIContainerCertificates -ContainerDN "LDAP://$sForestName/CN=AIA,$sPKSBase" -SourceLabel 'AIA'
                }
                $aIssuers = @($aAIACerts | Where-Object { $_.issuer } | ForEach-Object { $_.issuer } | Sort-Object -Unique)

                $aLocalRoots = @(Get-ChildItem Cert:\LocalMachine\Root | Where-Object {
                    # Ne garder que les Root CAs qui sont émetteurs d'un certificat AIA/NTAuth
                    $sCertSubject = $_.Subject
                    $aIssuers | Where-Object { $_ -eq $sCertSubject }
                })

                foreach ($oRootCert in $aLocalRoots) {
                    $aAllResults += [PSCustomObject][ordered]@{
                        source             = 'Root CA (local store)'
                        subject            = $oRootCert.Subject
                        issuer             = $oRootCert.Issuer
                        notBefore          = $oRootCert.NotBefore
                        notAfter           = $oRootCert.NotAfter
                        serialNumber       = $oRootCert.SerialNumber
                        thumbprint         = $oRootCert.Thumbprint
                        signatureAlgorithm = $oRootCert.SignatureAlgorithm.FriendlyName
                        keySize            = $oRootCert.PublicKey.Key.KeySize
                        version            = $oRootCert.Version
                        hasPrivateKey      = $oRootCert.HasPrivateKey
                        rawData             = [byte[]]$oRootCert.RawData
                    }
                }
            }
        }

        # --- KRA: Key Recovery Agents ---
        if ($Type -in @('All', 'KRA')) {
            Write-Verbose "Querying KRA..."
            $aKRA = Get-PKIContainerCertificates -ContainerDN "LDAP://$sForestName/CN=KRA,$sPKSBase" `
                -Filter '(objectClass=msPKI-PrivateKeyRecoveryAgent)' `
                -CertProperty 'userCertificate' -SourceLabel 'KRA'
            $aAllResults += $aKRA
        }

        # --- CDP: CRL Distribution Points ---
        if ($Type -in @('All', 'CDP')) {
            Write-Verbose "Querying CDP..."
            $sDN = "LDAP://$sForestName/CN=CDP,$sPKSBase"
            $oSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$sDN)
            $oSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
            $oSearcher.Filter = '(objectClass=cRLDistributionPoint)'
            $oSearcher.PageSize = 100
            $oSearcher.PropertiesToLoad.AddRange(@('cn', 'certificateRevocationList', 'deltaRevocationList', 'whenCreated', 'whenChanged', 'distinguishedName'))

            try {
                foreach ($oResult in $oSearcher.FindAll()) {
                    $sName = [string]$oResult.Properties['cn'][0]
                    $sDN = [string]$oResult.Properties['distinguishedname'][0]
                    # Extraire le nom de la CA parente depuis le DN (le container parent)
                    $sCAName = if ($sDN -match 'CN=[^,]+,CN=([^,]+),CN=CDP') { $Matches[1] } else { '' }

                    $bHasCRL = ($oResult.Properties['certificaterevocationlist'] -and $oResult.Properties['certificaterevocationlist'].Count -gt 0)
                    $bHasDelta = ($oResult.Properties['deltarevocationlist'] -and $oResult.Properties['deltarevocationlist'].Count -gt 0)
                    $aCRLData = [System.Collections.Generic.List[byte[]]]::new()
                    foreach ($oCRLValue in $oResult.Properties['certificaterevocationlist']) {
                        $aCRLData.Add([byte[]]$oCRLValue)
                    }
                    $aDeltaCRLData = [System.Collections.Generic.List[byte[]]]::new()
                    foreach ($oCRLValue in $oResult.Properties['deltarevocationlist']) {
                        $aDeltaCRLData.Add([byte[]]$oCRLValue)
                    }

                    $aAllResults += [PSCustomObject][ordered]@{
                        source      = "CDP/$sCAName"
                        distinguishedName = $sDN
                        subject     = $sName
                        issuer      = $sCAName
                        notBefore   = $oResult.Properties['whencreated'][0]
                        notAfter    = $oResult.Properties['whenchanged'][0]
                        hasCRL      = $bHasCRL
                        hasDeltaCRL = $bHasDelta
                        CRLData     = $aCRLData.ToArray()
                        DeltaCRLData = $aDeltaCRLData.ToArray()
                    }
                }
            } catch {
                Write-Verbose "Failed to query CDP: $_"
            }
        }

        return $aAllResults
    }
}
