function Get-ADComputer {
    <#
    .SYNOPSIS
        Retrieves AD computer objects using LDAP DirectorySearcher

    .DESCRIPTION
        Searches Active Directory for computer objects using System.DirectoryServices.
        Supports identity lookup, LDAP filter, or general filter. Can query via
        LDAP or Global Catalog protocol, with optional credentials.

    .PARAMETER Filter
        A PowerShell Where-Object filter applied to the results.

    .PARAMETER Credential
        PSCredential for authenticating to AD.

    .PARAMETER Properties
        Additional properties to load from AD.

    .PARAMETER ResultPageSize
        Page size for result pagination.

    .PARAMETER ResultSetSize
        Maximum number of results to return.

    .PARAMETER SearchBase
        The LDAP distinguished name to start searching from.

    .PARAMETER SearchScope
        The search scope (Base, OneLevel, Subtree).

    .PARAMETER Server
        The AD server or domain to connect to.

    .PARAMETER Identity
        The computer identity (sAMAccountName, objectGUID, or objectSid).

    .PARAMETER Partition
        The AD partition to search.

    .PARAMETER LDAPFilter
        A raw LDAP filter string.

    .PARAMETER UseGlobalCatalog
        If specified, uses the Global Catalog (GC://) instead of LDAP.

    .OUTPUTS
        System.DirectoryServices.SearchResult[]. The matching computer objects.

    .EXAMPLE
        Get-ADComputer -Identity "WORKSTATION01"

    .EXAMPLE
        Get-ADComputer -LDAPFilter "(operatingSystem=*Server*)" -Properties "operatingSystem"

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

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [ValidateNotNullOrEmpty()][ValidateRange(0,[Int32]::MaxValue)]
        [Int32]$ResultPageSize,

        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "LdapFilter")]
        [AllowNull][Int32]$ResultSetSize,

        [Parameter(ParameterSetName = "LdapFilter")]
        [Parameter(ParameterSetName = "Filter")]
        [ValidateNotNull()]
        [string]$SearchBase,

        [Parameter(ParameterSetName = "Filter")]
        [Parameter(ParameterSetName = "LdapFilter")]
        [ValidateNotNullOrEmpty()]
        [System.DirectoryServices.SearchScope]$SearchScope,

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

        [switch]$UseGlobalCatalog
    )
    Begin {
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

        function Split-DN {
            Param(
                [string]$DN
            )
            $iDC = $DN.IndexOf("DC=")
            if ($iDC -eq -1) {
                $iDC = $DN.IndexOf("dc=")
            }
            return [pscustomobject]@{
                Path = $DN.Substring(0, $iDC - 1)
                Domain = $DN.Substring($iDC)
            }
        }

        $sLdapProtocol = if ($UseGlobalCatalog.IsPresent) {
            "GC://"
        } else {
            "LDAP://"
        }

        $sIdentityDomain = if (($PSCmdlet.ParameterSetName -eq "Identity") -and ($Identity -match ".+,((dc|DC)=[^,]+)")) {
            (Split-DN $Identity).Domain
        } else {
            ""
        }
        
        $sServer = if ($Server) { 
            $sLdapProtocol + $Server 
        } elseif ($sIdentityDomain -ne "") {
            $sIdentityDomain
        } else {
            [System.DirectoryServices.DirectoryEntry] $de = New-Object System.DirectoryServices.DirectoryEntry($sLdapProtocol + "RootDSE")
            if ($sLdapProtocol -eq "LDAP://") {
                $sLdapProtocol + $de.Properties["defaultNamingContext"][0].ToString();
            } else {
                $sLdapProtocol + $de.Properties["rootDomainNamingContext"][0].ToString();
            }
        }
        $de = Connect-DirectoryEntry -Server $sServer -Credential $Credential
        $ds = New-Object System.DirectoryServices.DirectorySearcher($de);
        if ($ResultSetSize) {
            $ds.SizeLimit = $ResultSetSize
        }
        if ($ResultPageSize) {
            $ds.PageSize = $ResultPageSize
        }
        if ($SearchBase) {
            if ($SearchBase -match "[A-Za-z]+://.+") {
                $ds.SearchRoot = $SearchBase
            } else {
                $ds.SearchRoot = $sLdapProtocol + $SearchBase
            }
        }
        if ($SearchScope) {
            $ds.SearchScope = $SearchScope
        }
        foreach ($sProperty in $Properties) {
            $ds.PropertiesToLoad.Add($sProperty) | Out-Null
        }
        $sLdapFilter = switch ($PSCmdlet.ParameterSetName) {
            "Identity" {
                "(&(objectCategory=Computer)(objectClass=computer)(|(sAMAccountName=$Identity`$)(objectGUID=$IDentity)(objectSid=$Identity)))"
            }
            "LdapFilter" {
                $LDAPFilter
            }
            "Filter" {
                "(&(objectCategory=Computer)(objectClass=computer))"
            }
        }
        $ds.Filter = $sLdapFilter
    }
    Process {
        $oResult = $ds.FindAll()
        if ($Filter -and ($Filter -ne "*")) {
            $oResult = $oResult | Where-Object $Filter
        }
        return $oResult
    }
}
