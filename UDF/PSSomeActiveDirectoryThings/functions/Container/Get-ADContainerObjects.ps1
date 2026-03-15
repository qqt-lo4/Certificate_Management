function Get-ADContainerObjects {
    <#
    .SYNOPSIS
        Retrieves AD objects from a specific container or OU

    .DESCRIPTION
        Queries Active Directory for objects within a specified container DN.
        Supports filtering, pagination, recursive search, and Global Catalog queries.

    .PARAMETER ContainerDN
        The distinguished name of the container or OU to search.

    .PARAMETER Filter
        A filter string for Get-ADObject. Defaults to "*".

    .PARAMETER Properties
        Additional properties to retrieve.

    .PARAMETER ResultPageSize
        Page size for result pagination. Defaults to 1000.

    .PARAMETER ResultSetSize
        Maximum number of results to return.

    .PARAMETER Credential
        PSCredential for authenticating to AD.

    .PARAMETER Server
        The AD server or domain to connect to.

    .PARAMETER SearchScope
        The search scope. Defaults to OneLevel.

    .PARAMETER UseGlobalCatalog
        If specified, uses the Global Catalog.

    .PARAMETER LDAPFilter
        A raw LDAP filter string.

    .PARAMETER RecursiveSearch
        If specified, searches the entire subtree recursively.

    .OUTPUTS
        AD objects found in the specified container.

    .EXAMPLE
        Get-ADContainerObjects -ContainerDN "OU=Computers,DC=contoso,DC=com"

    .EXAMPLE
        Get-ADContainerObjects -ContainerDN "OU=Users,DC=contoso,DC=com" -RecursiveSearch -Properties "mail"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ContainerDN,
        
        [Parameter(Mandatory = $false)]
        [string]$Filter = "*",
        
        [Parameter(Mandatory = $false)]
        [string[]]$Properties,
        
        [Parameter(Mandatory = $false)]
        [int]$ResultPageSize = 1000,
        
        [Parameter(Mandatory = $false)]
        [int]$ResultSetSize,
        
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential,
        
        [Parameter(Mandatory = $false)]
        [string]$Server,
        
        [Parameter(Mandatory = $false)]
        [System.DirectoryServices.SearchScope]$SearchScope = [System.DirectoryServices.SearchScope]::OneLevel,
        
        [Parameter(Mandatory = $false)]
        [switch]$UseGlobalCatalog,
        
        [Parameter(Mandatory = $false)]
        [string]$LDAPFilter,
        
        [Parameter(Mandatory = $false)]
        [switch]$RecursiveSearch
    )
    
    # Define parameters to pass to Get-ADObject
    $params = @{
        SearchBase = $ContainerDN
        SearchScope = if ($RecursiveSearch) { [System.DirectoryServices.SearchScope]::Subtree } else { $SearchScope }
        ResultPageSize = $ResultPageSize
    }
    
    # Add optional parameters if provided
    if ($PSBoundParameters.ContainsKey('ResultSetSize')) { $params['ResultSetSize'] = $ResultSetSize }
    if ($PSBoundParameters.ContainsKey('Credential')) { $params['Credential'] = $Credential }
    if ($PSBoundParameters.ContainsKey('Server')) { $params['Server'] = $Server }
    if ($PSBoundParameters.ContainsKey('Properties')) { $params['Properties'] = $Properties }
    if ($PSBoundParameters.ContainsKey('Filter')) { $params['Filter'] = $Filter }
    if ($PSBoundParameters.ContainsKey('LDAPFilter')) { $params['LDAPFilter'] = $LDAPFilter }
    if ($UseGlobalCatalog) { $params['UseGlobalCatalog'] = $true }
    
    try {
        # Call Get-ADObject with the parameters
        $objects = Get-ADObject @params
        
        return $objects
    }
    catch {
        Write-Error "Error retrieving objects from container $ContainerDN : $($_.Exception.Message)"
    }
}