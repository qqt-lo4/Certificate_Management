function Get-ADUser {
    <#
    .SYNOPSIS
        Searches for AD user objects

    .DESCRIPTION
        Wrapper around Get-ADObject that automatically filters for user objects.
        Supports identity lookup, LDAP filter, simple filter, and path-based queries
        with optional Global Catalog search.

    .PARAMETER Filter
        A filter string to search for users.

    .PARAMETER Credential
        Credentials to use for the directory query.

    .PARAMETER Properties
        The properties to retrieve for each user.

    .PARAMETER AdditionalProperties
        Additional properties to retrieve beyond the defaults.

    .PARAMETER Path
        An ADS path to retrieve a specific user.

    .PARAMETER Strict
        If specified, uses exact matching for filters.

    .PARAMETER ResultPageSize
        The number of results per page for paged searches.

    .PARAMETER ResultSetSize
        The maximum number of results to return.

    .PARAMETER SearchBase
        The DN of the search base.

    .PARAMETER SearchScope
        The scope of the search (Base, OneLevel, Subtree).

    .PARAMETER Server
        The domain controller or domain to query.

    .PARAMETER Identity
        The identity of the user (name, DN, UPN, GUID, or SID).

    .PARAMETER Partition
        The naming context partition to search.

    .PARAMETER LDAPFilter
        An LDAP filter string to search for users.

    .PARAMETER UseGlobalCatalog
        If specified, searches the Global Catalog instead of the domain.

    .OUTPUTS
        [object]. One or more AD user objects.

    .EXAMPLE
        Get-ADUser -Identity "jdoe" -Properties "mail", "department"

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
    return (Get-ADObject @PSBoundParameters -User)
}
