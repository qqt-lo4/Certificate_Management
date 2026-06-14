function Get-ADOU {
    <#
    .SYNOPSIS
        Searches for AD organizational unit objects.

    .DESCRIPTION
        Wrapper around Get-ADObject that automatically filters for
        organizationalUnit objects via the -OU switch.

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
        The search scope (Base, OneLevel, Subtree). Defaults to Subtree.

    .PARAMETER Server
        The AD server or domain to connect to.

    .PARAMETER Identity
        OU identity (DN, GUID, or name).

    .PARAMETER Partition
        The AD partition to search.

    .PARAMETER LDAPFilter
        A raw LDAP filter string.

    .PARAMETER UseGlobalCatalog
        If specified, uses the Global Catalog (GC://).

    .PARAMETER SecurityMasks
        Pass-through to Get-ADObject so callers can request the
        nTSecurityDescriptor (or other security-protected attributes).

    .OUTPUTS
        Custom AD organizationalUnit object(s).

    .EXAMPLE
        Get-ADOU -Server contoso.com

    .EXAMPLE
        Get-ADOU -Server contoso.com -Properties 'distinguishedName', 'description'

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        1.0.0 (2026-05-20) - Initial version
    #>
    [CmdletBinding(DefaultParameterSetName = "Filter")]
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

        [Parameter()]
        [System.DirectoryServices.SecurityMasks]$SecurityMasks
    )
    return (Get-ADObject @PSBoundParameters -OU)
}
