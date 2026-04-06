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
        Object identity (sAMAccountName, DN, GUID, SID, CN, or UPN).

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
        Version : 1.0.0
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
        [AllowNull][Int32]$ResultSetSize,

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
        [string]$Identity,

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
        [switch]$Computer,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "Identity")]
        [switch]$User,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "Identity")]
        [switch]$OU,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "Identity")]
        [switch]$Container,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "Identity")]
        [switch]$Volume,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "Identity")]
        [switch]$Group,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "Identity")]
        [switch]$Contact,

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
                [string]$Identity
            )
            $hTypes = @{
                "Computer" = "(&(objectCategory=Computer)(objectClass=computer))"
                "User" = "(&(objectCategory=User)(objectClass=user))"
                "OU" = "(&(objectCategory=Organizational-Unit)(objectClass=organizationalUnit))"
                "Container" = "(&(objectCategory=Container)(objectClass=container))"
                "Volume" = "(&(objectCategory=Volume)(objectClass=volume))"
                "Group" = "(&(objectCategory=Group)(objectClass=group))"
                "Contact" = "(&(objectCategory=Person)(objectClass=contact))"
            }
            if ($Computer -or $User -or $OU -or $Container -or $Volume -or $Group -or $Contact) {
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
            
            if ($Identity) {
                #$sResult = "(&" + $sResult + "(|(sAMAccountName=$Identity)(objectGUID=$IDentity)(objectSid=$Identity)(cn=$Identity)(name=$Identity)))"
				$sResult = "(&" + $sResult + "(|(sAMAccountName=$Identity)(objectGUID=$IDentity)(objectSid=$Identity)(cn=$Identity)(name=$Identity)(userPrincipalName=$Identity)))"
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
        $bDN = ($PSCmdlet.ParameterSetName -eq "Identity") -and ($Identity -match ".+,((dc|DC)=[^,]+)")
        if ($PSCmdlet.ParameterSetName -ne "Path") {
            if ($bDN) {
                $sPath += $Identity
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
        if ($Properties) {
            $ds.PropertiesToLoad.Add("objectclass") | Out-Null
            foreach ($sProperty in $Properties) {
                $ds.PropertiesToLoad.Add($sProperty) | Out-Null
            }
        }
        $sLdapFilter = switch ($PSCmdlet.ParameterSetName) {
            "Path" {
                ""
            }
            "Identity" {
                if ($bDN) {
                    Get-LdapFilter -Computer:$Computer -User:$User -OU:$Ou -Container:$Container -Volume:$Volume -Group:$Group -Contact:$Contact
                } else {
                    Get-LdapFilter -Computer:$Computer -User:$User -OU:$Ou -Container:$Container -Volume:$Volume -Group:$Group -Contact:$Contact -Identity $Identity
                }
            }
            "LdapFilter" {
                $LDAPFilter
            }
            "Filter" {
                Get-LdapFilter -Computer:$Computer -User:$User -OU:$Ou -Container:$Container -Volume:$Volume -Group:$Group -Contact:$Contact
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
