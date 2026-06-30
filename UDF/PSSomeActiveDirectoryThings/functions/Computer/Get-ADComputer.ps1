function Get-ADComputer {
    <#
    .SYNOPSIS
        Searches for AD computer objects

    .DESCRIPTION
        Wrapper around Get-ADObject that automatically filters for computer objects.
        Supports identity lookup, LDAP filter, simple filter, and path-based queries
        with optional Global Catalog search.

    .PARAMETER Filter
        A filter string to search for computers.

    .PARAMETER Credential
        Credentials to use for the directory query.

    .PARAMETER Properties
        The properties to retrieve for each computer.

    .PARAMETER AdditionalProperties
        Additional properties to retrieve beyond the defaults.

    .PARAMETER Path
        An ADS path to retrieve a specific computer.

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
        The identity of the computer (name, DN, GUID, or SID).

    .PARAMETER Partition
        The naming context partition to search.

    .PARAMETER LDAPFilter
        An LDAP filter string to search for computers.

    .PARAMETER UseGlobalCatalog
        If specified, searches the Global Catalog instead of the domain.

    .PARAMETER SecurityMasks
        Pass-through to Get-ADObject so callers can request security-protected
        attributes (e.g. nTSecurityDescriptor).

    .OUTPUTS
        [object]. One or more AD computer objects.

    .EXAMPLE
        Get-ADComputer -Identity "WORKSTATION01" -Properties "operatingSystem"

    .EXAMPLE
        Get-ADComputer -LDAPFilter "(operatingSystem=*Server*)" -Properties "operatingSystem"

    .NOTES
        Author  : Loïc Ade
        Version : 2.0.0

        CHANGELOG:

        Version 2.0.0 - 2026-06-15 - Loïc Ade
            - Rewritten as a thin wrapper around Get-ADObject -Computer (same model
              as Get-ADUser), replacing the standalone DirectorySearcher
              implementation. Adds -Path, -AdditionalProperties and -SecurityMasks
              support and returns the same custom AD objects as Get-ADObject.

        Version 1.0.0 - Loïc Ade
            - Initial release (standalone LDAP DirectorySearcher implementation).
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

        # Pass-through to Get-ADObject so callers can request the
        # nTSecurityDescriptor (or other security-protected attributes).
        [Parameter()]
        [System.DirectoryServices.SecurityMasks]$SecurityMasks
    )
    return (Get-ADObject @PSBoundParameters -Computer)
}
