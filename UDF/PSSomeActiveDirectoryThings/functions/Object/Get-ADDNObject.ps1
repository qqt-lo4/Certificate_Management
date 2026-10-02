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

    .PARAMETER SearchScope
        Directory search scope forwarded to Get-ADObject. Default: Base
        (returns only the entries named by the DNs). Pass Subtree when the
        goal is "resolve these DNs AND everything underneath them".

    .OUTPUTS
        Custom AD object(s) resolved from the DN list.

    .EXAMPLE
        $g = Get-ADObject -Identity "CN=Test,OU=Groups,DC=lan,DC=example,DC=com"
        Get-ADDNObject -DN $g.member

    .NOTES
        Author  : Loïc Ade
        Version : 2.1.0

        CHANGELOG:

        Version 2.1.0 - 2026-07-10 - Loïc Ade
            - New -SearchScope parameter (no default). Forwarded to
              Get-ADObject only when the caller explicitly sets it, so
              Get-ADObject applies its own per-mode default: Base for the
              single-DN fast path (avoids pulling every descendant of the
              resolved entry - a user's ExchangeActiveSyncDevices, etc.),
              Subtree for the batch-DN path (whose filter needs to see the
              whole domain subtree, otherwise every multi-member group
              came back empty). Callers wanting descendants of a specific
              DN pass -SearchScope Subtree explicitly.
            - Isolate per-domain failures. An unreachable trusted subdomain
              made Get-ADObject throw "cannot invoke method on null-valued
              expression" (defaultNamingContext[0].ToString() on an empty
              RootDSE response), which propagated out and killed the whole
              caller (Get-GroupMembers dropped every member of any group
              whose DN list spanned a reachable and an unreachable domain).
              A try/catch around the per-domain lookup logs a warning
              naming the domain and continues with the other domains.

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
        [switch]$UseGlobalCatalog,

        # Forwarded to Get-ADObject when explicitly set. Get-ADObject picks a
        # sensible default per-call: Base for its single-DN fast path (avoids
        # pulling every child under the resolved entry - a user's
        # ExchangeActiveSyncDevices, an OU's children, ...), and Subtree for
        # the batch-DN path (whose filter needs to see the whole domain
        # subtree). Set explicitly only to override those defaults.
        [System.DirectoryServices.SearchScope]$SearchScope
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
            # ContainsKey rather than "if ($SearchScope)": Base is enum 0
            # (falsy). We only forward when the caller actually specified
            # it, so Get-ADObject picks its per-mode default otherwise.
            if ($PSBoundParameters.ContainsKey('SearchScope')) {
                $hGetADObjectArgs.SearchScope = $SearchScope
            }
            # Per-domain isolation: an unreachable subdomain (RootDSE lookup fails,
            # defaultNamingContext comes back empty and .ToString() on the missing
            # value throws "cannot invoke method on a null-valued expression") must
            # not abort the whole batch. A group with members split across several
            # trusted domains still gets every reachable member; the unreachable
            # ones are surfaced as one warning naming the domain and the DN count.
            try {
                $aResults += Get-ADObject @hGetADObjectArgs
            } catch {
                Write-Warning "Get-ADDNObject: domain '$sDomain' unreachable ($($aDomainDN.Count) DN(s) skipped) - $($_.Exception.Message)"
            }
        }
    }
    Process {

    }
    End {
        return $aResults
    }
}
