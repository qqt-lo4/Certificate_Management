function Get-ADGroup {
    <#
    .SYNOPSIS
        Retrieves AD group objects

    .DESCRIPTION
        Searches Active Directory for group objects using identity, LDAP filter,
        or general filter. Wraps Get-ADObject with the -Group switch.

    .PARAMETER Filter
        A PowerShell filter applied to results.

    .PARAMETER Credential
        PSCredential for AD authentication.

    .PARAMETER Properties
        Properties to load from AD.

    .PARAMETER AdditionalProperties
        Extra properties to add to the result.

    .PARAMETER Path
        Direct LDAP path to the group.

    .PARAMETER Strict
        If specified, enables strict matching.

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
        The group identity (name, DN, GUID, or SID).

    .PARAMETER Partition
        The AD partition to search.

    .PARAMETER LDAPFilter
        A raw LDAP filter string.

    .PARAMETER UseGlobalCatalog
        If specified, uses the Global Catalog.

    .OUTPUTS
        Custom AD group object(s).

    .EXAMPLE
        Get-ADGroup -Identity "Domain Admins"

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
        [switch]$UseGlobalCatalog
    )
    return (Get-ADObject @PSBoundParameters -Group)
}
