function Get-CertificateTemplateDetails {
    <#
    .SYNOPSIS
        Retrieves certificate templates from AD with decoded configuration details.

    .DESCRIPTION
        Gets all certificate templates from the AD forest configuration and decodes
        the raw AD attributes into human-readable fields: key usage, validity period,
        renewal period, enrollment flags, name flags, private key flags, etc.

    .PARAMETER NameFilter
        Regex filter to match against template names. Optional.

    .OUTPUTS
        [PSCustomObject[]] Templates with decoded configuration properties.

    .EXAMPLE
        Get-CertificateTemplateDetails

    .EXAMPLE
        Get-CertificateTemplateDetails -NameFilter "WebServer|Computer"

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-03-30) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [string]$NameFilter
    )

    Process {
        # --- Helper: decode pKIExpirationPeriod / pKIOverlapPeriod (FILETIME byte array) ---
        function ConvertFrom-PKIPeriod {
            Param([byte[]]$Bytes)
            if (-not $Bytes -or $Bytes.Count -ne 8) { return $null }
            $iValue = [BitConverter]::ToInt64($Bytes, 0)
            # Value is negative 100-nanosecond intervals
            $tsSpan = [TimeSpan]::FromTicks(-$iValue)
            if ($tsSpan.TotalDays -ge 365) {
                $iYears = [Math]::Round($tsSpan.TotalDays / 365, 1)
                return "$iYears year(s)"
            } elseif ($tsSpan.TotalDays -ge 1) {
                return "$([int]$tsSpan.TotalDays) day(s)"
            } else {
                return "$([int]$tsSpan.TotalHours) hour(s)"
            }
        }

        # --- Helper: decode pKIKeyUsage byte array to flags ---
        function ConvertFrom-KeyUsage {
            Param([byte[]]$Bytes)
            if (-not $Bytes -or $Bytes.Count -lt 1) { return $null }
            $iVal = [int]$Bytes[0]
            if ($Bytes.Count -ge 2) { $iVal = $iVal -bor ([int]$Bytes[1] -shl 8) }
            $aFlags = @()
            if ($iVal -band 0x80)  { $aFlags += "Digital Signature" }
            if ($iVal -band 0x40)  { $aFlags += "Non Repudiation" }
            if ($iVal -band 0x20)  { $aFlags += "Key Encipherment" }
            if ($iVal -band 0x10)  { $aFlags += "Data Encipherment" }
            if ($iVal -band 0x08)  { $aFlags += "Key Agreement" }
            if ($iVal -band 0x04)  { $aFlags += "Certificate Signing" }
            if ($iVal -band 0x02)  { $aFlags += "CRL Signing" }
            if ($iVal -band 0x01)  { $aFlags += "Encipher Only" }
            if ($aFlags.Count -eq 0) { return "None" }
            return $aFlags -join ", "
        }

        # --- Helper: decode msPKI-Enrollment-Flag ---
        function ConvertFrom-EnrollmentFlags {
            Param([int]$Value)
            $aFlags = @()
            if ($Value -band 0x00000001) { $aFlags += "IncludeSymmetricAlgorithms" }
            if ($Value -band 0x00000002) { $aFlags += "PendAllRequests" }
            if ($Value -band 0x00000004) { $aFlags += "PublishToKRAContainer" }
            if ($Value -band 0x00000008) { $aFlags += "PublishToDS" }
            if ($Value -band 0x00000010) { $aFlags += "AutoEnrollmentCheckUserDSCertificate" }
            if ($Value -band 0x00000020) { $aFlags += "AutoEnrollment" }
            if ($Value -band 0x00000100) { $aFlags += "PreviousApprovalValidateReenrollment" }
            if ($Value -band 0x00000400) { $aFlags += "UserInteractionRequired" }
            if ($Value -band 0x00004000) { $aFlags += "RemoveInvalidCertificateFromPersonalStore" }
            if ($Value -band 0x00010000) { $aFlags += "NoSecurityExtension" }
            if ($aFlags.Count -eq 0) { return "None" }
            return $aFlags -join ", "
        }

        # --- Helper: decode msPKI-Certificate-Name-Flag ---
        function ConvertFrom-NameFlags {
            Param([long]$Value)
            # Convert from signed int32 to unsigned
            if ($Value -lt 0) { $Value = $Value + 4294967296 }
            $aFlags = @()
            if ($Value -band 0x00000001) { $aFlags += "EnrolleeSuppliesSubject" }
            if ($Value -band 0x00010000) { $aFlags += "EnrolleeSuppliesSubjectAltName" }
            if ($Value -band 0x00400000) { $aFlags += "SubjectAltRequireDNS" }
            if ($Value -band 0x00800000) { $aFlags += "SubjectAltRequireEmail" }
            if ($Value -band 0x01000000) { $aFlags += "SubjectAltRequireSPN" }
            if ($Value -band 0x02000000) { $aFlags += "SubjectAltRequireDirectoryGUID" }
            if ($Value -band 0x04000000) { $aFlags += "SubjectAltRequireUPN" }
            if ($Value -band 0x08000000) { $aFlags += "SubjectRequireEmail" }
            if ($Value -band 0x10000000) { $aFlags += "SubjectRequireDNS" }
            if ($Value -band 0x40000000) { $aFlags += "SubjectRequireCommonName" }
            if ($Value -band 0x80000000) { $aFlags += "SubjectRequireDirectoryPath" }
            if ($aFlags.Count -eq 0) { return "None" }
            return $aFlags -join ", "
        }

        # --- Helper: decode msPKI-Private-Key-Flag ---
        function ConvertFrom-PrivateKeyFlags {
            Param([int]$Value)
            $aFlags = @()
            if ($Value -band 0x00000001) { $aFlags += "RequirePrivateKeyArchival" }
            if ($Value -band 0x00000010) { $aFlags += "ExportableKey" }
            if ($Value -band 0x00000020) { $aFlags += "StrongKeyProtectionRequired" }
            if ($Value -band 0x00000040) { $aFlags += "RequireAlternateSignatureAlgorithm" }
            if ($Value -band 0x00000080) { $aFlags += "RequireSameKeyRenewal" }
            if ($Value -band 0x00000100) { $aFlags += "UseLegacyProvider" }
            if ($Value -band 0x00001000) { $aFlags += "AttestNone" }
            if ($Value -band 0x00002000) { $aFlags += "AttestSoftware" }
            if ($Value -band 0x00004000) { $aFlags += "AttestHardware" }
            if ($Value -band 0x00008000) { $aFlags += "AttestTPM" }
            if ($aFlags.Count -eq 0) { return "None" }
            return $aFlags -join ", "
        }

        # Query templates with all relevant properties
        $sForestName = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name
        $oForest = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$sForestName")
        $sForestDN = $oForest.distinguishedName
        $sCertTemplatesDN = "LDAP://$sForestName/CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$sForestDN"

        $aProperties = @(
            'name', 'displayName', 'flags',
            'msPKI-Cert-Template-OID', 'revision',
            'msPKI-Template-Schema-Version', 'msPKI-Template-Minor-Revision',
            'pKIKeyUsage', 'pKIExpirationPeriod', 'pKIOverlapPeriod',
            'pKIMaxIssuingDepth', 'pKIDefaultKeySpec', 'pKIDefaultCSPs',
            'msPKI-Enrollment-Flag', 'msPKI-Certificate-Name-Flag', 'msPKI-Private-Key-Flag',
            'msPKI-RA-Signature', 'msPKI-Minimal-Key-Size',
            'pKIExtendedKeyUsage', 'pKICriticalExtensions',
            'msPKI-Certificate-Application-Policy', 'msPKI-RA-Application-Policies',
            'msPKI-Supersede-Templates',
            'whenCreated', 'whenChanged',
            'nTSecurityDescriptor'
        )

        $aTemplates = Get-ADContainerObjects -ContainerDN $sCertTemplatesDN -Properties $aProperties `
            -SecurityMasks ([System.DirectoryServices.SecurityMasks]::Dacl)

        if ($NameFilter) {
            $aTemplates = @($aTemplates | Where-Object { $_.Name -match $NameFilter })
        }

        # EKU OID lookup
        $hEKU = @{
            '1.3.6.1.5.5.7.3.1'  = 'Server Authentication'
            '1.3.6.1.5.5.7.3.2'  = 'Client Authentication'
            '1.3.6.1.5.5.7.3.3'  = 'Code Signing'
            '1.3.6.1.5.5.7.3.4'  = 'Secure Email'
            '1.3.6.1.5.5.7.3.8'  = 'Time Stamping'
            '1.3.6.1.5.5.7.3.9'  = 'OCSP Signing'
            '1.3.6.1.4.1.311.10.3.4'  = 'EFS Encryption'
            '1.3.6.1.4.1.311.10.3.12' = 'Document Signing'
            '1.3.6.1.4.1.311.20.2.2'  = 'Smart Card Logon'
            '2.5.29.37.0'             = 'Any Purpose'
        }

        function Resolve-EKU {
            Param($OIDs)
            if (-not $OIDs) { return $null }
            $aResolved = @($OIDs | ForEach-Object {
                if ($hEKU.ContainsKey($_)) { "$($hEKU[$_]) ($_)" } else { $_ }
            })
            return $aResolved -join ", "
        }

        # --- Helper: extract enrollment permissions from ACL ---
        function Get-EnrollmentPermissions {
            Param($SecurityDescriptor)
            if (-not $SecurityDescriptor) { return @{ Enroll = $null; AutoEnroll = $null } }

            # Certificate enrollment/autoenrollment GUIDs
            $sEnrollGuid      = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
            $sAutoEnrollGuid  = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

            $aEnroll = @()
            $aAutoEnroll = @()

            try {
                # Si c'est un tableau de bytes, le convertir en ActiveDirectorySecurity
                $oACL = if ($SecurityDescriptor -is [byte[]]) {
                    $oSD = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    $oSD.SetSecurityDescriptorBinaryForm($SecurityDescriptor)
                    $oSD
                } elseif ($SecurityDescriptor -is [System.DirectoryServices.ActiveDirectorySecurity]) {
                    $SecurityDescriptor
                } else {
                    # Tenter la conversion depuis un tableau d'objets (Convert-ADObjectValue peut retourner un object[])
                    $aBytes = [byte[]]$SecurityDescriptor
                    $oSD = New-Object System.DirectoryServices.ActiveDirectorySecurity
                    $oSD.SetSecurityDescriptorBinaryForm($aBytes)
                    $oSD
                }

                foreach ($oACE in $oACL.Access) {
                    if ($oACE.AccessControlType -ne 'Allow') { continue }
                    $sIdentity = $oACE.IdentityReference.ToString()

                    if ($oACE.ObjectType -and $oACE.ObjectType.ToString() -eq $sEnrollGuid) {
                        $aEnroll += $sIdentity
                    }
                    if ($oACE.ObjectType -and $oACE.ObjectType.ToString() -eq $sAutoEnrollGuid) {
                        $aAutoEnroll += $sIdentity
                    }
                }
            } catch {
                Write-Verbose "Failed to parse ACL: $_"
            }

            return @{
                Enroll     = if ($aEnroll.Count -gt 0) { $aEnroll -join '; ' } else { $null }
                AutoEnroll = if ($aAutoEnroll.Count -gt 0) { $aAutoEnroll -join '; ' } else { $null }
            }
        }

        # Build result objects
        $aResults = foreach ($oTpl in $aTemplates) {
            $iSchemaVersion = $oTpl.'msPKI-Template-Schema-Version'
            $iKeySpec = $oTpl.pKIDefaultKeySpec
            $sKeySpec = switch ($iKeySpec) {
                1 { "AT_KEYEXCHANGE" }
                2 { "AT_SIGNATURE" }
                default { $iKeySpec }
            }

            # Decode enrollment permissions
            $hPerms = Get-EnrollmentPermissions $oTpl.nTSecurityDescriptor

            # Application policies (decoded like EKU)
            $sAppPolicy = Resolve-EKU $oTpl.'msPKI-Certificate-Application-Policy'

            # Superseded templates
            $sSupersedes = if ($oTpl.'msPKI-Supersede-Templates') {
                ($oTpl.'msPKI-Supersede-Templates' -join ', ')
            } else { $null }

            [PSCustomObject][ordered]@{
                name                 = $oTpl.Name
                displayName          = $oTpl.displayName
                schemaVersion        = $iSchemaVersion
                templateOID          = $oTpl.'msPKI-Cert-Template-OID'
                validity             = ConvertFrom-PKIPeriod $oTpl.pKIExpirationPeriod
                renewalPeriod        = ConvertFrom-PKIPeriod $oTpl.pKIOverlapPeriod
                minimumKeySize       = $oTpl.'msPKI-Minimal-Key-Size'
                keySpec              = $sKeySpec
                keyUsage             = ConvertFrom-KeyUsage $oTpl.pKIKeyUsage
                extendedKeyUsage     = Resolve-EKU $oTpl.pKIExtendedKeyUsage
                applicationPolicy    = $sAppPolicy
                enrollmentFlags      = ConvertFrom-EnrollmentFlags ([int]$oTpl.'msPKI-Enrollment-Flag')
                nameFlags            = ConvertFrom-NameFlags ([long]$oTpl.'msPKI-Certificate-Name-Flag')
                privateKeyFlags      = ConvertFrom-PrivateKeyFlags ([int]$oTpl.'msPKI-Private-Key-Flag')
                raSignaturesRequired = $oTpl.'msPKI-RA-Signature'
                maxIssuingDepth      = $oTpl.pKIMaxIssuingDepth
                cryptoProviders      = if ($oTpl.pKIDefaultCSPs) { ($oTpl.pKIDefaultCSPs -join ", ") } else { $null }
                enrollPermissions    = $hPerms.Enroll
                autoEnrollPermissions = $hPerms.AutoEnroll
                supersedesTemplates  = $sSupersedes
                whenCreated          = $oTpl.whenCreated
                whenChanged          = $oTpl.whenChanged
            }
        }

        return @($aResults | Sort-Object name)
    }
}
