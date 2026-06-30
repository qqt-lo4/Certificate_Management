function Get-ADDNObject {
    <#
    .SYNOPSIS
        Retrieves AD objects from a list of distinguished names

    .DESCRIPTION
        Queries Active Directory to resolve a list of distinguished names into
        full AD objects. Automatically groups DNs by domain for efficient querying
        across multi-domain forests. Supports Global Catalog and additional properties.

    .PARAMETER Credential
        PSCredential for AD authentication.

    .PARAMETER Properties
        Properties to load from AD.

    .PARAMETER AdditionalProperties
        Extra properties loaded in a separate query and merged into results.

    .PARAMETER Server
        The AD server to connect to. Cannot be used when DNs span multiple domains.

    .PARAMETER DN
        The distinguished name(s) to resolve.

    .PARAMETER UseGlobalCatalog
        If specified, uses the Global Catalog (GC://). Aliases: GC, GlobalCatalog.

    .OUTPUTS
        Custom AD object(s) resolved from the DN list.

    .EXAMPLE
        $g = Get-ADObject -Identity "CN=Test,OU=Groups,DC=lan,DC=example,DC=com"
        Get-ADDNObject -DN $g.member

    .NOTES
        Author  : Loïc Ade
        Version : 2.0.0

        CHANGELOG:

        Version 2.0.0 - 2026-06-16 - Loïc Ade
            - Refactored as a thin wrapper around Get-ADObject (now that it accepts a
              batch [string[]] -Identity). DNs are grouped by domain and each group is
              resolved by one Get-ADObject call. Removes the duplicate, divergent
              object builder: resolved objects are now ordinary Get-ADObject objects
              (hashtable shape, Refresh(), full PSTypeNames including "ADObject").
              Fixes drilled-in views (e.g. a managed user opened from "List managed
              users") where computed attributes silently came back empty and the
              logon-status tests threw, because the old PSCustomObject lacked the
              "ADObject" type token and could not accept lazily-added properties.

        Version 1.0.0 - Loïc Ade
            - First version.
    #>
    
    Param(
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]$Credential,

        [ValidateNotNullOrEmpty()]
        [Alias("Property")]
        [string[]]$Properties,

        [ValidateNotNullOrEmpty()]
        [string[]]$AdditionalProperties,

        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [ValidateNotNull()]
        [string[]]$DN,

        [Alias("GC", "GlobalCatalog")]
        [switch]$UseGlobalCatalog
    )
    Begin {
        # Resolve the DN list through Get-ADObject so the whole module has a SINGLE
        # AD-object builder (object shape, Refresh(), PSTypeNames). DNs are grouped by
        # domain so a multi-domain forest is queried once per domain; Get-ADObject's
        # batch -Identity OR-s the per-DN clauses (it matches distinguishedName) into a
        # single query per domain.
        $aGroupedDN = Group-DNByDomain -DNList $DN
        if ($Server -and ($aGroupedDN.Count -gt 1)) {
            throw "Can't specify server : there is more than one domain in the DN list"
        }
        $aResults = @()
        foreach ($oDomainGroup in $aGroupedDN.GetEnumerator()) {
            $sDomain   = $oDomainGroup.Key
            $aDomainDN = @($oDomainGroup.Value)
            $hGetADObjectArgs = @{
                Identity = $aDomainDN
                Server   = if ($Server) { $Server } else { $sDomain }
            }
            if ($Properties)           { $hGetADObjectArgs.Properties = $Properties }
            if ($AdditionalProperties) { $hGetADObjectArgs.AdditionalProperties = $AdditionalProperties }
            if ($Credential)           { $hGetADObjectArgs.Credential = $Credential }
            if ($UseGlobalCatalog)     { $hGetADObjectArgs.UseGlobalCatalog = $true }
            $aResults += Get-ADObject @hGetADObjectArgs
        }
    }
    Process {

    }
    End {
        return $aResults
    }
}
