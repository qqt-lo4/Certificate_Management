function Resolve-ADObject {
    <#
    .SYNOPSIS
        Resolves one or more "DOMAIN\Name" tokens to their AD objects.
        Streams resolved objects; warns and skips entries whose
        DOMAIN prefix is not a known forest domain (or throws when
        -StrictPrefix is set).

    .DESCRIPTION
        Several Windows / inventory tools (SCCM, ACL
        identityReference fields, logon tokens, ...) tag every
        identity with a "DOMAIN\Name" prefix. Downstream consumers
        usually need to look the underlying AD object up - to
        classify by objectclass, follow group membership, fetch
        attributes, etc. This helper turns the token list into
        resolved AD objects with the minimum number of round-trips:

          1. Builds the forest's NetBIOS -> DNS map once via
             Get-ADDomainNetBIOSMap (or accepts a pre-built map
             through -NetBIOSMap to amortise across nested calls).
          2. Validates each DOMAIN prefix against the map. Both
             prefix styles are accepted:
               - NetBIOS short name ("CORP\jdoe") matches a Key.
               - DNS form ("corp.example.com\jdoe") matches a Value.
             Unknown prefixes (local server accounts like
             FILER01\Administrator, unrelated forests, ...) are
             dropped with a Write-Warning by default - or rethrown
             when -StrictPrefix is set, so per-identity callers can
             react.
          3. Groups validated identities by DNS domain and calls
             Get-ADObject -Server <DNS> -Identity <SAM[]> once per
             domain. The targeted -Server arg restricts the query
             to that domain's NamingContext, so Configuration-
             partition objects sharing the SAM (cert templates etc.)
             do not enter the result set - the canonical
             pKICertificateTemplate "Administrator" trap that bare
             Get-ADObject -Identity -UseGlobalCatalog falls into.
          4. Streams every resolved object. Unresolved (valid prefix
             but missing name) identities yield nothing; the caller
             can compare emitted count against input count to know.

        Pipeline-friendly: `$tokens | Resolve-ADObject` works the
        same as `-Identity $tokens`.

    .PARAMETER Identity
        One or more "DOMAIN\Name" identity tokens. Single string or
        array, both accepted; pipeline input is also accepted.

    .PARAMETER Credential
        Optional credentials forwarded to Get-ADDomainNetBIOSMap and
        every Get-ADObject lookup.

    .PARAMETER NetBIOSMap
        Optional pre-built NetBIOS -> DNS map (the hashtable
        returned by Get-ADDomainNetBIOSMap). Pass when calling
        Resolve-ADObject inside a tight loop so the forest map is
        built once rather than per call.

    .PARAMETER Properties
        Properties to fetch on each returned object, forwarded as-is
        to Get-ADObject. When omitted, Get-ADObject's default
        property set is returned (DistinguishedName, Name,
        ObjectClass, ObjectGUID).

    .PARAMETER StrictPrefix
        When set, an unknown DOMAIN prefix throws instead of being
        warned-and-skipped. Use in per-identity classifiers that
        want to catch the throw and react (e.g. classify the
        identity as 'local' on a server). The default behaviour
        (warn + skip) suits bulk perimeter resolution where best-
        effort coverage is acceptable.

    .OUTPUTS
        Stream of resolved AD objects, one per identity that
        validated and was found in its prefixed domain.

    .EXAMPLE
        # Bulk, best-effort: skip unknown prefixes with a warning.
        $aObjects = @('CORP\jdoe','CORP\PC-001','EU\asmith' |
            Resolve-ADObject -Credential $oCred)

    .EXAMPLE
        # Per-identity classifier - rethrow on unknown prefix so the
        # caller can map it to a local-account bucket.
        try {
            $oObj = Resolve-ADObject -Identity $sId -StrictPrefix -NetBIOSMap $hMap
            if ($oObj) { $sType = "$($oObj.objectclass)" }
        } catch {
            $sType = 'local'
        }

    .EXAMPLE
        # DNS-form prefix also accepted (forest map values are
        # scanned when the Keys lookup misses).
        Resolve-ADObject -Identity 'corp.example.com\jdoe'

    .EXAMPLE
        # Fetch extra attributes alongside the default set.
        Resolve-ADObject -Identity 'CORP\jdoe' `
            -Properties displayName,mail,memberOf

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-06-12, Loic Ade) - Unified successor to
                             Resolve-ADObjects (plural, wrapper-
                             returning) and Resolve-ADIdentity
                             (singular, throw-on-prefix). Streams
                             objects directly, accepts pipeline
                             input, exposes the two error modes via
                             -StrictPrefix. The plural-wrapper
                             ScopeDomains computation moves to the
                             caller (one-liner DN parse).
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position=0, ValueFromPipeline)]
        [string[]]$Identity,

        [PSCredential]$Credential,

        [hashtable]$NetBIOSMap,

        [string[]]$Properties,

        [switch]$StrictPrefix
    )

    Begin {
        $hCredParam = @{}
        if ($Credential) { $hCredParam['Credential'] = $Credential }
        if (-not $NetBIOSMap) {
            $NetBIOSMap = Get-ADDomainNetBIOSMap @hCredParam
        }

        # -Properties is optional: when not supplied, Get-ADObject
        # returns its default property set. Build the splatted
        # extra-args hashtable here so the End block stays clean.
        $hProps = @{}
        if ($Properties) { $hProps['Properties'] = $Properties }

        # Per-call accumulator: identity SAMs grouped by their
        # resolved DNS domain. Flushed via batched Get-ADObject in
        # End, so streaming many small inputs through the pipeline
        # still benefits from per-domain batching.
        $hByDns = @{}
    }

    Process {
        foreach ($t in $Identity) {
            $parts = $t -split '\\', 2
            if ($parts.Count -ne 2 -or -not $parts[0] -or -not $parts[1]) {
                if ($StrictPrefix) {
                    throw "Resolve-ADObject : '$t' is not in DOMAIN\Name form."
                }
                Write-Warning "Resolve-ADObject : '$t' has no DOMAIN\Name prefix - skipped."
                continue
            }
            $sPrefix = $parts[0]
            $sName   = $parts[1]

            # NetBIOS short name first (Keys are the canonical
            # lookup), then DNS-form scan over Values. PowerShell
            # hashtable lookups and -ieq are both case-insensitive
            # on strings, so casing variants resolve transparently.
            $sDns = $null
            if ($NetBIOSMap.ContainsKey($sPrefix)) {
                $sDns = $NetBIOSMap[$sPrefix]
            } else {
                foreach ($sValue in $NetBIOSMap.Values) {
                    if ($sValue -ieq $sPrefix) { $sDns = $sValue; break }
                }
            }
            if (-not $sDns) {
                if ($StrictPrefix) {
                    throw "Resolve-ADObject : prefix '$sPrefix' (from '$t') is not a known AD NetBIOS / DNS domain in the forest - identity is likely a local account on a non-AD host."
                }
                Write-Warning "Resolve-ADObject : prefix '$sPrefix' (from '$t') is not a known AD NetBIOS / DNS domain - skipped."
                continue
            }
            if (-not $hByDns.ContainsKey($sDns)) { $hByDns[$sDns] = @() }
            $hByDns[$sDns] += $sName
        }
    }

    End {
        # Batch-resolve per DNS domain. One DirectoryEntry connection
        # per domain regardless of how many identities share it.
        # Get-ADObject's -Identity already accepts [string[]] and OR-s
        # the per-id LDAP disjunctions.
        foreach ($sDns in $hByDns.Keys) {
            try {
                $aResults = @(Get-ADObject @hCredParam -Server $sDns -Identity ([string[]]$hByDns[$sDns]) @hProps)
                foreach ($oRes in $aResults) { $oRes }
            } catch {
                Write-Warning "Resolve-ADObject : batch @ $sDns - $($_.Exception.Message)"
            }
        }
    }
}
