function Get-ADGroupPolicyNetworkProfile {
    <#
    .SYNOPSIS
        Extracts wireless (802.11) and wired (802.3) network profiles
        deployed by a GPO.

    .DESCRIPTION
        Both policy families live as AD objects directly under the GPO's
        Machine container (not in SYSVOL like other GPO content):

            CN=<policy-id>,CN={Wireless|Wired},CN=Windows,CN=Microsoft,
            CN=Machine,CN={GPO-id},CN=Policies,CN=System,DC=...

        The msieee80211-Data attribute (resp. msieee8023-Data) contains
        a Unicode XML document describing one or more network profiles
        per the MS-GPWL spec. The function returns one row per profile,
        flattening the CMMC-relevant decision points: SSID, auth type,
        encryption, 802.1X enablement, EAP method, server-certificate
        validation, and a count of trusted-root references.

        XML namespace handling uses local-name() XPath so the function
        is resilient to schema-version drift; we never bind to a
        specific namespace URI.

    .PARAMETER GPOId
        The GPO's CN as stored under CN=Policies,CN=System (the curly-
        braced GUID, e.g. "{2A4D75CB-7CFB-4A53-89E1-0E1A9EFB16B0}").

    .PARAMETER Server
        Domain FQDN to query.

    .PARAMETER Credential
        Optional PSCredential. Reuses the calling identity by default.

    .OUTPUTS
        PSCustomObject[] with properties:
            PolicyType                ('Wireless' | 'Wired')
            PolicyName                (msieee80211-ID friendly name)
            ProfileName               (per-profile name; one row per profile)
            SSID                      (Wi-Fi only; $null for wired)
            ConnectionType            ('ESS' | 'IBSS' | $null)
            ConnectionMode            ('auto' | 'manual' | $null)
            Authentication            ('open' | 'WPA' | 'WPA2' | 'WPA3'
                                       | 'WPAPSK' | 'WPA2PSK' | 'WPA3SAE' | ...)
            Encryption                ('none' | 'WEP' | 'TKIP' | 'AES'
                                       | 'GCMP256' | ...)
            UseOneX                   (bool; 802.1X enabled)
            OneXAuthMode              ('machine' | 'user' | 'machineOrUser'
                                       | 'guest' | $null)
            EapMethodCode             (int; e.g. 13=EAP-TLS, 25=PEAP, 26=EAP-MSCHAPv2)
            EapMethodName             (decoded label or "Type=<code>")
            ValidateServerCertificate (bool | $null)
            TrustedRootHashCount      (int; number of SHA-1 hashes referenced)

        Returns nothing when no msieee80211-Policy / msieee8023-Policy
        objects exist under the GPO container (the common case for
        non-network GPOs).

    .EXAMPLE
        Get-ADGroupPolicyNetworkProfile -GPOId '{2A4D75CB-7CFB-4A53-89E1-0E1A9EFB16B0}' `
            -Server 'stago.grp'

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-05-27) - Initial version. Wireless schema per
                             MS-GPWL; wired schema is similar enough
                             that the same flattening logic applies
                             (most wired profiles omit SSID and skip
                             the OneXConfig branch).
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$GPOId,

        [Parameter(Mandatory)]
        [string]$Server,

        [AllowNull()]
        [PSCredential]$Credential
    )

    Process {
        # EAP method code -> friendly name (RFC 3748 / IANA registry,
        # plus Microsoft's own ranges). Unknown codes pass through as
        # "Type=<code>" so callers see something rather than $null.
        $hEapMethods = @{
            13 = 'EAP-TLS'
            17 = 'LEAP'
            18 = 'EAP-SIM'
            21 = 'EAP-TTLS'
            23 = 'EAP-AKA'
            25 = 'PEAP'
            26 = 'EAP-MSCHAPv2'
            29 = 'EAP-PSK'
            43 = 'EAP-FAST'
            47 = 'EAP-PWD'
            50 = 'EAP-AKA-Prime'
        }

        # Decode the msieee80211-Data / msieee8023-Data attribute into
        # a usable XML string. Schema says Octet String (byte[]) holding
        # UTF-16 LE XML, but some AD module versions surface it as a
        # pre-decoded string. Handle both shapes plus the single-element
        # array case.
        function ConvertFrom-PolicyData {
            Param($Raw)
            if ($null -eq $Raw) { return $null }
            if ($Raw -is [string]) { return $Raw }
            if ($Raw -is [byte[]]) {
                return ([System.Text.Encoding]::Unicode.GetString($Raw)).TrimStart([char]0xFEFF, [char]0)
            }
            if ($Raw -is [System.Array] -and $Raw.Count -ge 1) {
                $oFirst = $Raw[0]
                if ($oFirst -is [byte[]]) {
                    return ([System.Text.Encoding]::Unicode.GetString($oFirst)).TrimStart([char]0xFEFF, [char]0)
                }
                return "$oFirst"
            }
            return "$Raw"
        }

        # XPath text extraction that ignores namespace. Returns $null
        # when the element is absent rather than throwing - many of the
        # paths below are optional in the schema.
        function Get-XmlChildText {
            Param([System.Xml.XmlNode]$Node, [string]$Path)
            if (-not $Node) { return $null }
            $oFound = $Node.SelectSingleNode($Path)
            if (-not $oFound) { return $null }
            return $oFound.InnerText
        }

        # Resolve domain DN via RootDSE so the SearchBase below points
        # at the right naming context. Reuses Get-DirectoryEntry from
        # the module so -Credential plumbing is consistent.
        $sRootDSEPath = "LDAP://$Server/RootDSE"
        $oRootDSE = Get-DirectoryEntry -Path $sRootDSEPath -Credential $Credential
        $sDomainDN = $oRootDSE.Properties["defaultNamingContext"][0].ToString()
        $sSearchBase = "CN=$GPOId,CN=Policies,CN=System,$sDomainDN"

        # Common AD query params - reused for both wireless and wired.
        $hAdParams = @{
            Server      = $Server
            SearchBase  = $sSearchBase
            SearchScope = 'Subtree'
        }
        if ($Credential) { $hAdParams['Credential'] = $Credential }

        # Schema availability cache, keyed by "<server>|wlan" / "|wired".
        # Forests that never applied the Wireless / Wired Group Policy
        # schema extension reject Get-ADObject with LDAP_NO_SUCH_ATTRIBUTE
        # ("L'attribut ou la valeur ... n'existe pas") because the
        # requested Properties name (msieee80211-Data /
        # msieee8023-Data) is not in the schema. The error is a .NET
        # exception from FindAll() that ErrorAction can't suppress,
        # so the schema is probed ONCE per server up front and the
        # corresponding query is skipped when the attribute is absent.
        # $global: scope lets the cache survive Import-Module -Force
        # during iterative development; Clear-ADNetworkProfileSchemaCache
        # resets it.
        if ($null -eq $global:ADNetworkProfileSchema) {
            $global:ADNetworkProfileSchema = @{}
        }
        $sCacheKeyWlan  = "$($Server.ToLower())|wlan"
        $sCacheKeyWired = "$($Server.ToLower())|wired"

        # First-touch probe: a single Get-ADObject on the schema NC
        # tells us whether the wireless / wired attribute is present
        # without trying it against every GPO. Two probes worst case
        # (one per family) per server per session.
        if (-not $global:ADNetworkProfileSchema.ContainsKey($sCacheKeyWlan) -or
            -not $global:ADNetworkProfileSchema.ContainsKey($sCacheKeyWired)) {
            try {
                $hRootParams = @{ Server = $Server }
                if ($Credential) { $hRootParams['Credential'] = $Credential }
                $sSchemaDN = (Get-ADRootDSE @hRootParams).schemaNamingContext

                $hProbeParams = @{
                    Server      = $Server
                    SearchBase  = $sSchemaDN
                    SearchScope = 'OneLevel'
                    Properties  = 'name'
                    ErrorAction = 'SilentlyContinue'
                }
                if ($Credential) { $hProbeParams['Credential'] = $Credential }

                if (-not $global:ADNetworkProfileSchema.ContainsKey($sCacheKeyWlan)) {
                    $iWlan = @(Get-ADObject @hProbeParams -LDAPFilter '(lDAPDisplayName=msieee80211-Data)').Count
                    $global:ADNetworkProfileSchema[$sCacheKeyWlan] = ($iWlan -gt 0)
                }
                if (-not $global:ADNetworkProfileSchema.ContainsKey($sCacheKeyWired)) {
                    $iWired = @(Get-ADObject @hProbeParams -LDAPFilter '(lDAPDisplayName=msieee8023-Data)').Count
                    $global:ADNetworkProfileSchema[$sCacheKeyWired] = ($iWired -gt 0)
                }
            } catch {
                # Probe itself failed (connectivity, ACL on schema NC,
                # ...): default both families to unavailable so we
                # neither retry nor query. The verbose log surfaces
                # the why if -Verbose is on.
                Write-Verbose "Get-ADGroupPolicyNetworkProfile : schema probe failed on $Server - $($_.Exception.Message)"
                if (-not $global:ADNetworkProfileSchema.ContainsKey($sCacheKeyWlan)) {
                    $global:ADNetworkProfileSchema[$sCacheKeyWlan] = $false
                }
                if (-not $global:ADNetworkProfileSchema.ContainsKey($sCacheKeyWired)) {
                    $global:ADNetworkProfileSchema[$sCacheKeyWired] = $false
                }
            }
        }

        # ---- Wireless policies (msieee80211-Policy) --------------------
        $aWlanPolicies = @()
        if ($global:ADNetworkProfileSchema[$sCacheKeyWlan]) {
            $hWlanParams = @{} + $hAdParams
            $hWlanParams['LDAPFilter'] = '(objectClass=msieee80211-Policy)'
            $hWlanParams['Properties'] = @('msieee80211-Data', 'msieee80211-ID', 'name')
            try {
                $aWlanPolicies = @(Get-ADObject @hWlanParams)
            } catch {
                # Defensive: schema probe said the attribute is present
                # but the per-GPO query still threw (ACL, transient
                # error, ...). Log and continue with empty.
                Write-Verbose "Get-ADGroupPolicyNetworkProfile : wireless query failed on $sSearchBase - $($_.Exception.Message)"
            }
        }
        foreach ($oPolicy in $aWlanPolicies) {
            $sXml = ConvertFrom-PolicyData $oPolicy.'msieee80211-Data'
            if (-not $sXml) { continue }
            $oXml = $null
            try { $oXml = [xml]$sXml } catch {
                Write-Warning "Get-ADGroupPolicyNetworkProfile : malformed WLAN XML on $($oPolicy.DistinguishedName) - $_"
                continue
            }
            $sPolicyName = if ($oPolicy.'msieee80211-ID') { "$($oPolicy.'msieee80211-ID')" } else { "$($oPolicy.name)" }

            # WLAN profiles can live at various depths depending on the
            # schema version; descendant lookup finds them all.
            foreach ($oProf in $oXml.SelectNodes("//*[local-name()='Profile']")) {
                $sProfName = Get-XmlChildText $oProf "./*[local-name()='name']"
                $sSSID     = Get-XmlChildText $oProf ".//*[local-name()='SSIDConfig']/*[local-name()='SSID']/*[local-name()='name']"
                $sConnType = Get-XmlChildText $oProf "./*[local-name()='connectionType']"
                $sConnMode = Get-XmlChildText $oProf "./*[local-name()='connectionMode']"
                $sAuth     = Get-XmlChildText $oProf ".//*[local-name()='authentication']"
                $sEnc      = Get-XmlChildText $oProf ".//*[local-name()='encryption']"
                $sUseOneX  = Get-XmlChildText $oProf ".//*[local-name()='useOneX']"
                $bUseOneX  = if ($null -ne $sUseOneX) { [string]::Equals($sUseOneX, 'true', 'OrdinalIgnoreCase') } else { $null }
                $sAuthMode = Get-XmlChildText $oProf ".//*[local-name()='OneX']/*[local-name()='authMode']"
                $sEapType  = Get-XmlChildText $oProf ".//*[local-name()='EapMethod']/*[local-name()='Type']"
                $iEap      = 0
                $bEapOk    = if ($sEapType) { [int]::TryParse($sEapType, [ref]$iEap) } else { $false }
                $sValidate = Get-XmlChildText $oProf ".//*[local-name()='ValidateServerCert']"
                $bValidate = if ($null -ne $sValidate) { [string]::Equals($sValidate, 'true', 'OrdinalIgnoreCase') } else { $null }
                $iTrusted  = @($oProf.SelectNodes(".//*[local-name()='TrustedRootCA']")).Count

                [PSCustomObject][ordered]@{
                    PolicyType                = 'Wireless'
                    PolicyName                = $sPolicyName
                    ProfileName               = $sProfName
                    SSID                      = $sSSID
                    ConnectionType            = $sConnType
                    ConnectionMode            = $sConnMode
                    Authentication            = $sAuth
                    Encryption                = $sEnc
                    UseOneX                   = $bUseOneX
                    OneXAuthMode              = $sAuthMode
                    EapMethodCode             = if ($bEapOk) { $iEap } else { $null }
                    EapMethodName             = if ($bEapOk) {
                        if ($hEapMethods.ContainsKey($iEap)) { $hEapMethods[$iEap] } else { "Type=$iEap" }
                    } else { $null }
                    ValidateServerCertificate = $bValidate
                    TrustedRootHashCount      = $iTrusted
                }
            }
        }

        # ---- Wired policies (msieee8023-Policy) ------------------------
        $aWiredPolicies = @()
        if ($global:ADNetworkProfileSchema[$sCacheKeyWired]) {
            $hWiredParams = @{} + $hAdParams
            $hWiredParams['LDAPFilter'] = '(objectClass=msieee8023-Policy)'
            $hWiredParams['Properties'] = @('msieee8023-Data', 'msieee8023-ID', 'name')
            try {
                $aWiredPolicies = @(Get-ADObject @hWiredParams)
            } catch {
                Write-Verbose "Get-ADGroupPolicyNetworkProfile : wired query failed on $sSearchBase - $($_.Exception.Message)"
            }
        }
        foreach ($oPolicy in $aWiredPolicies) {
            $sXml = ConvertFrom-PolicyData $oPolicy.'msieee8023-Data'
            if (-not $sXml) { continue }
            $oXml = $null
            try { $oXml = [xml]$sXml } catch {
                Write-Warning "Get-ADGroupPolicyNetworkProfile : malformed wired XML on $($oPolicy.DistinguishedName) - $_"
                continue
            }
            $sPolicyName = if ($oPolicy.'msieee8023-ID') { "$($oPolicy.'msieee8023-ID')" } else { "$($oPolicy.name)" }

            foreach ($oProf in $oXml.SelectNodes("//*[local-name()='LANProfile']")) {
                $sProfName = Get-XmlChildText $oProf ".//*[local-name()='name']"
                # Wired has no SSID. authMode + EAP live under OneX same way.
                $sUseOneX  = Get-XmlChildText $oProf ".//*[local-name()='useOneX']"
                $bUseOneX  = if ($null -ne $sUseOneX) { [string]::Equals($sUseOneX, 'true', 'OrdinalIgnoreCase') } else { $null }
                $sAuthMode = Get-XmlChildText $oProf ".//*[local-name()='OneX']/*[local-name()='authMode']"
                $sEapType  = Get-XmlChildText $oProf ".//*[local-name()='EapMethod']/*[local-name()='Type']"
                $iEap      = 0
                $bEapOk    = if ($sEapType) { [int]::TryParse($sEapType, [ref]$iEap) } else { $false }
                $sValidate = Get-XmlChildText $oProf ".//*[local-name()='ValidateServerCert']"
                $bValidate = if ($null -ne $sValidate) { [string]::Equals($sValidate, 'true', 'OrdinalIgnoreCase') } else { $null }
                $iTrusted  = @($oProf.SelectNodes(".//*[local-name()='TrustedRootCA']")).Count

                [PSCustomObject][ordered]@{
                    PolicyType                = 'Wired'
                    PolicyName                = $sPolicyName
                    ProfileName               = $sProfName
                    SSID                      = $null
                    ConnectionType            = $null
                    ConnectionMode            = $null
                    Authentication            = $null
                    Encryption                = $null
                    UseOneX                   = $bUseOneX
                    OneXAuthMode              = $sAuthMode
                    EapMethodCode             = if ($bEapOk) { $iEap } else { $null }
                    EapMethodName             = if ($bEapOk) {
                        if ($hEapMethods.ContainsKey($iEap)) { $hEapMethods[$iEap] } else { "Type=$iEap" }
                    } else { $null }
                    ValidateServerCertificate = $bValidate
                    TrustedRootHashCount      = $iTrusted
                }
            }
        }
    }
}
