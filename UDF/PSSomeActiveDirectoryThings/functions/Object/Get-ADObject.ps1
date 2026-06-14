function Get-ADObject {
    <#
    .SYNOPSIS
        Retrieves AD objects using LDAP DirectorySearcher

    .DESCRIPTION
        Core function for searching Active Directory using System.DirectoryServices.
        Supports identity, LDAP filter, path, or general filter lookups with object
        type filtering (User, Computer, Group, OU, etc.). Returns custom AD objects
        with a Refresh() method and typed PSTypeNames.

    .PARAMETER Filter
        A PowerShell Where-Object filter applied to results.

    .PARAMETER Credential
        PSCredential for AD authentication.

    .PARAMETER Properties
        Properties to load from AD.

    .PARAMETER AdditionalProperties
        Extra properties loaded in a separate query and merged into results.

    .PARAMETER Path
        Direct LDAP/GC path to an object.

    .PARAMETER Strict
        If specified, only returns objects whose path matches the search root exactly.

    .PARAMETER ResultPageSize
        Page size for result pagination.

    .PARAMETER ResultSetSize
        Maximum number of results.

    .PARAMETER SearchBase
        The DN to start searching from.

    .PARAMETER SearchScope
        The search scope (Base, OneLevel, Subtree).

    .PARAMETER Server
        The AD server or domain to connect to.

    .PARAMETER Identity
        Object identity, or an array of identities for a single
        batch lookup. Each entry can be a sAMAccountName, DN,
        GUID, SID, CN, name, or UPN; the LDAP filter is built as
        an OR of every per-identity disjunction. Use this batch
        form to avoid one DirectoryEntry connection per object
        when resolving a large perimeter (group your identities
        by domain on the caller side and pass each group to a
        single Get-ADObject call with the corresponding -Server).
        DN-style identities are only honoured in the single-value
        form: when you pass several DNs in one call the function
        falls back to the filter-based search.

    .PARAMETER Partition
        The AD partition to search.

    .PARAMETER LDAPFilter
        A raw LDAP filter string.

    .PARAMETER UseGlobalCatalog
        If specified, uses the Global Catalog (GC://).

    .PARAMETER Computer
        Filter to computer objects.

    .PARAMETER User
        Filter to user objects.

    .PARAMETER OU
        Filter to organizational units.

    .PARAMETER Container
        Filter to container objects.

    .PARAMETER Volume
        Filter to volume objects.

    .PARAMETER Group
        Filter to group objects.

    .PARAMETER Contact
        Filter to contact objects.

    .PARAMETER GroupPolicy
        Filter to Group Policy container objects.

    .PARAMETER WMIFilter
        Filter to WMI filter SOM objects (msWMI-Som). These live under
        CN=SOM,CN=WMIPolicy,CN=System,<domainDN> and back the WMI
        filters referenced by GPO gPCWQLFilter attributes.

    .PARAMETER SecurityMasks
        Controls which security descriptor parts are returned when requesting nTSecurityDescriptor.
        By default, the DirectorySearcher does not return security descriptors. Set this to
        [System.DirectoryServices.SecurityMasks]::Dacl to retrieve the permissions (ACL), which
        is required for reading who can Enroll/AutoEnroll on certificate templates, for example.
        Possible values: None, Owner, Group, Dacl, Sacl.

    .OUTPUTS
        Custom AD object(s) with typed PSTypeNames and Refresh() method.

    .EXAMPLE
        Get-ADObject -Identity "jdoe" -User

    .EXAMPLE
        Get-ADObject -LDAPFilter "(department=IT)" -Properties "mail","department"

    .NOTES
        Author  : Loïc Ade
        Version : 1.1.0

        1.1.0 (2026-06-03, Loïc Ade) - -Identity now accepts
                             [string[]] so a single call can resolve
                             a batch of objects in one
                             DirectoryEntry connection. Get-LdapFilter
                             OR-s the per-identity disjunctions.
                             DN-binding via path stays available
                             for the single-value form; the batch
                             form always uses the filter route.

        1.0.0 - Initial version.
    #>
    [CmdletBinding(DefaultParameterSetName="Filter")]
    Param(
        [Parameter(ParameterSetName = "Filter")]
        [string]$Filter,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]$Credential,

        [ValidateNotNullOrEmpty()]
        [Alias("Property")]
        [string[]]$Properties,

        [ValidateNotNullOrEmpty()]
        [string[]]$AdditionalProperties,

        [Parameter(ParameterSetName = "Path")]
        [ValidateNotNull()]
        [string]$Path,
        
        [ValidateNotNull()]
        [switch]$Strict,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [ValidateNotNullOrEmpty()][ValidateRange(0,[Int32]::MaxValue)]
        [Int32]$ResultPageSize,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [AllowNull()][Int32]$ResultSetSize,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [ValidateNotNull()]
        [string]$SearchBase,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [ValidateNotNullOrEmpty()]
        [System.DirectoryServices.SearchScope]$SearchScope,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "Identity")]
        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = "Identity")]
        [ValidateNotNull()]
        [string[]]$Identity,

        [Parameter(ParameterSetName = "Identity")]
        [ValidateNotNullOrEmpty()]
        [string]$Partition,

        [Parameter(Mandatory, ParameterSetName = "LdapFilter")]
        [ValidateNotNullOrEmpty()]
        [string]$LDAPFilter,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "Identity")]
        [switch]$UseGlobalCatalog,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "Identity")]
        [Parameter(ParameterSetName = "Path")]
        [switch]$Computer,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "Identity")]
        [Parameter(ParameterSetName = "Path")]
        [switch]$User,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "Identity")]
        [Parameter(ParameterSetName = "Path")]
        [switch]$OU,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "Identity")]
        [Parameter(ParameterSetName = "Path")]
        [switch]$Container,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "Identity")]
        [Parameter(ParameterSetName = "Path")]
        [switch]$Volume,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "Identity")]
        [Parameter(ParameterSetName = "Path")]
        [switch]$Group,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "Identity")]
        [Parameter(ParameterSetName = "Path")]
        [switch]$Contact,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "Identity")]
        [Parameter(ParameterSetName = "Path")]
        [switch]$GroupPolicy,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "Identity")]
        [Parameter(ParameterSetName = "Path")]
        [switch]$WMIFilter,

        [Parameter()]
        [System.DirectoryServices.SecurityMasks]$SecurityMasks
    )
    Begin {
        function Get-LdapFilter {
            Param(
                [switch]$Computer,
                [switch]$User,
                [switch]$OU,
                [switch]$Container,
                [switch]$Volume,
                [switch]$Group,
                [switch]$Contact,
                [switch]$GroupPolicy,
                [switch]$WMIFilter,
                # [string[]] now: when more than one identity is
                # supplied the function OR-s every per-identity
                # disjunction so a single DirectoryEntry connection
                # resolves the whole batch.
                [string[]]$Identity
            )
            # The CN-shortcut for objectCategory (e.g., 'Organizational-Unit'
            # → CN=Organizational-Unit,CN=Schema,...) relies on AD's implicit
            # schema resolution and has been observed to silently fail for OU
            # in some forests, returning 0 rows. objectClass alone is reliable
            # (organizationalUnit is a structural class) so we drop the
            # objectCategory clause for OU. The other entries keep it because
            # objectCategory is indexed and single-valued, so it's faster, and
            # they've been observed to work in practice.
            $hTypes = @{
                "Computer" = "(&(objectCategory=Computer)(objectClass=computer))"
                "User" = "(&(objectCategory=User)(objectClass=user))"
                "OU" = "(objectClass=organizationalUnit)"
                "Container" = "(&(objectCategory=Container)(objectClass=container))"
                "Volume" = "(&(objectCategory=Volume)(objectClass=volume))"
                "Group" = "(&(objectCategory=Group)(objectClass=group))"
                "Contact" = "(&(objectCategory=Person)(objectClass=contact))"
                "GroupPolicy" = "(objectClass=groupPolicyContainer)"
                "WMIFilter" = "(objectClass=msWMI-Som)"
            }
            if ($Computer -or $User -or $OU -or $Container -or $Volume -or $Group -or $Contact -or $GroupPolicy -or $WMIFilter) {
                $sResult = "(|"
                foreach ($sParam in $PSBoundParameters.Keys) {
                    if ($PSBoundParameters[$sParam]) {
                        $sResult += $hTypes[$sParam]
                    }
                }
                $sResult += ")"
            } else {
                $sResult = ""
            }
            
            if ($Identity -and $Identity.Count -gt 0) {
                # Per-identity disjunction = one OR clause across
                # the six lookup attributes (sAM, GUID, SID, CN,
                # name, UPN). For a batch we wrap every per-id
                # clause in an outer OR so the whole filter still
                # matches "any object resolving any of the inputs".
                # @(...) guards against PS unwrapping a 1-element
                # foreach result to a bare string - without it,
                # $aIdentityClauses[0] would return the first char.
                $aIdentityClauses = @(foreach ($sId in $Identity) {
                    "(|(sAMAccountName=$sId)(objectGUID=$sId)(objectSid=$sId)(cn=$sId)(name=$sId)(userPrincipalName=$sId))"
                })
                $sIdentityFilter = if ($aIdentityClauses.Count -eq 1) {
                    $aIdentityClauses[0]
                } else {
                    '(|' + ($aIdentityClauses -join '') + ')'
                }
                $sResult = '(&' + $sResult + $sIdentityFilter + ')'
            }
            return $sResult
        }

        function Connect-DirectoryEntry {
            Param(
                [Parameter(Mandatory)]
                [string]$Server,
                [AllowNull()]
                [pscredential]$Credential
            )
            [System.DirectoryServices.DirectoryEntry] $de = if ($Credential) {
                $sUsername = $Credential.UserName
                $sUnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password))
                New-Object System.DirectoryServices.DirectoryEntry($Server, $sUsername, $sUnsecurePassword)
            } else {
                New-Object System.DirectoryServices.DirectoryEntry($Server)
            }
            return $de
        }

        $sLdapProtocol = if ($UseGlobalCatalog.IsPresent) { "GC://" } else { "LDAP://" }

        $sPath = if ($Path) {
            $Path
        } elseif ($Server) { 
            $sLdapProtocol + $Server + "/"
        } else {
            $sLdapProtocol
        }
        # DN-path binding is the fast path: when the caller passes
        # the exact DN, we attach it to the LDAP path instead of
        # building a search filter. Only meaningful for a single
        # identity - in the batch form we always go through the
        # filter route since multiple DNs can't share one path.
        $bDN = ($PSCmdlet.ParameterSetName -eq "Identity") `
            -and (@($Identity).Count -eq 1) `
            -and ($Identity[0] -match ".+,((dc|DC)=[^,]+)")
        if ($PSCmdlet.ParameterSetName -ne "Path") {
            if ($bDN) {
                $sPath += $Identity[0]
            } else {
                # Read RootDSE from the target server (or local domain if no server specified)
                $sRootDSEPath = if ($Server) { $sLdapProtocol + $Server + "/RootDSE" } else { $sLdapProtocol + "RootDSE" }
                [System.DirectoryServices.DirectoryEntry] $de = New-Object System.DirectoryServices.DirectoryEntry($sRootDSEPath)
                $sPath += if ($sLdapProtocol -eq "LDAP://") {
                    $de.Properties["defaultNamingContext"][0].ToString();
                } else {
                    $de.Properties["rootDomainNamingContext"][0].ToString();
                }
            }
        }

        $de = Connect-DirectoryEntry -Server $sPath -Credential $Credential
        $ds = New-Object System.DirectoryServices.DirectorySearcher($de);
        if ($ResultSetSize) { $ds.SizeLimit = $ResultSetSize }
        if ($ResultPageSize) { $ds.PageSize = $ResultPageSize }
        if ($SearchScope) { $ds.SearchScope = $SearchScope }
        if ($SearchBase) {
            if ($SearchBase -match "[A-Za-z]+://.+") {
                $ds.SearchRoot = $SearchBase
            } else {
                $ds.SearchRoot = $sLdapProtocol + $SearchBase
            }
        }
        if ($PSBoundParameters.ContainsKey('SecurityMasks')) { $ds.SecurityMasks = $SecurityMasks }
        # In Path mode, the DirectoryEntry is bound to a specific DN. The default
        # subtree search would return its children — force Base scope so the
        # entry itself is returned, with a wildcard filter so it matches.
        if ($PSCmdlet.ParameterSetName -eq "Path" -and -not $SearchScope) {
            $ds.SearchScope = [System.DirectoryServices.SearchScope]::Base
        }
        if ($Properties) {
            $ds.PropertiesToLoad.Add("objectclass") | Out-Null
            foreach ($sProperty in $Properties) {
                $ds.PropertiesToLoad.Add($sProperty) | Out-Null
            }
        }
        $sLdapFilter = switch ($PSCmdlet.ParameterSetName) {
            "Path" {
                "(objectClass=*)"
            }
            "Identity" {
                if ($bDN) {
                    Get-LdapFilter -Computer:$Computer -User:$User -OU:$Ou -Container:$Container -Volume:$Volume -Group:$Group -Contact:$Contact -GroupPolicy:$GroupPolicy -WMIFilter:$WMIFilter
                } else {
                    Get-LdapFilter -Computer:$Computer -User:$User -OU:$Ou -Container:$Container -Volume:$Volume -Group:$Group -Contact:$Contact -GroupPolicy:$GroupPolicy -WMIFilter:$WMIFilter -Identity $Identity
                }
            }
            "LdapFilter" {
                $LDAPFilter
            }
            "Filter" {
                Get-LdapFilter -Computer:$Computer -User:$User -OU:$Ou -Container:$Container -Volume:$Volume -Group:$Group -Contact:$Contact -GroupPolicy:$GroupPolicy -WMIFilter:$WMIFilter
            }
        }
        $ds.Filter = $sLdapFilter
    }
    Process {
        $aADResults = $ds.FindAll()
        if ($Filter -and ($Filter -ne "*")) {
            $aADResults = $aADResults | Where-Object $Filter
        }
        if ($Strict.IsPresent) {
            $aADResults = $aADResults | Where-Object { $_.Path -like $sPath }
        }
        if ($AdditionalProperties) {
            $ds.PropertiesToLoad.Clear()
            foreach ($sProperty in $AdditionalProperties) {
                $ds.PropertiesToLoad.Add($sProperty) | Out-Null
            }
            $aADResultsAdditionalProp = $ds.FindAll()
            if ($Filter -and ($Filter -ne "*")) {
                $aADResultsAdditionalProp = $aADResultsAdditionalProp | Where-Object $Filter
            }
            if ($Strict.IsPresent) {
                $aADResultsAdditionalProp = $aADResultsAdditionalProp | Where-Object { $_.Path -like $sPath }
            }
        } else {
            $aADResultsAdditionalProp = $null
        }
    }
    End {
        $aResults = @()
        $defaultDisplaySet = 'distinguishedname','givenname','name','objectclass','objectguid','samaccountname','objectsid','sn','userprincipalname'
        $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet',[string[]]$defaultDisplaySet)
        $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)

        foreach ($oResult in $aADResults) {
            $hADObject = [ordered]@{
                AdditionalProperties = @{
                    Path = $oResult.Path
                    SearchResult = $oResult
                    Properties = @()
                }
            }
            $aKeys = $oResult.Properties.Keys | Sort-Object
            foreach ($p in $aKeys) {
                $hADObject[$p] = Convert-ADObjectValue -Property $p -Value ($oResult.Properties[$p])
                $hADObject.AdditionalProperties.Properties += $p
            }
            if ($aADResultsAdditionalProp) {
                $oAdditionalPropResult = $aADResultsAdditionalProp | Where-Object { $_.Properties.adspath[0] -eq $oResult.Properties.adspath[0] }
                foreach ($p in $oAdditionalPropResult.Properties.Keys) {
                    $hADObject[$p] = Convert-ADObjectValue -Property $p -Value ($oAdditionalPropResult.Properties[$p])
                }   
            }
            $oNewResult = $hADObject
            $oNewResult | Add-Member MemberSet PSStandardMembers $PSStandardMembers
            $oNewResult | Add-Member -MemberType ScriptMethod -Name Refresh -Value {
                $aAdditionalProperties = $this.Keys | Where-Object { $_ -ne "AdditionalProperties" }
                $o = Get-ADObject -Path $this.AdditionalProperties.Path -AdditionalProperties $aAdditionalProperties
                $aKeys = $o.Keys | Where-Object { $_ -ne "AdditionalProperties" }
                $hAdditionalProperties = @{
                    Path = $this.AdditionalProperties.Path
                    SearchResult = $o.AdditionalProperties.SearchResult
                    Properties = $aKeys
                }
                $this.Clear()
                $this.AdditionalProperties = $hAdditionalProperties
                foreach ($sKey in $aKeys) {
                    $this.$sKey = $o.$sKey
                }
            }
            $oNewResult.psobject.TypeNames.Insert(0, "ADObject")
            if ($oNewResult.objectclass) {
                $oNewResult.psobject.TypeNames.Insert(0, $oNewResult.objectclass)
                $oNewResult.psobject.TypeNames.Insert(0, "AD" + $oNewResult.objectclass)
            }
            $aResults += $oNewResult 
        }
        return $aResults
    }
}
