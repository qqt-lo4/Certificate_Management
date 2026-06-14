function Resolve-ADSidName {
    <#
    .SYNOPSIS
        Resolves a Windows SID to its NT account name (cached).

    .DESCRIPTION
        Translates a Security Identifier (S-1-...) to its DOMAIN\Name form
        through System.Security.Principal.SecurityIdentifier.Translate.
        Resolution uses the local LSA, which for a domain-joined host
        forwards unknown SIDs to the domain controller; well-known SIDs
        resolve without any network call.

        Returns $null when resolution fails (orphaned account, foreign
        forest the local LSA can't reach, malformed SID). Callers
        typically render the raw SID when this happens.

        Results are memoised in $global:ADSidNameCache. The global scope
        (rather than the module scope) is deliberate: a script that runs
        with Import-Module -Force during iterative development would
        otherwise drop the cache on every reload. With a global, the cache
        survives Import-Module -Force and only resets when the host
        process exits or Clear-ADSidNameCache is called explicitly. Null
        is cached too, so the same dead SID is not retried.

        Pass -NoCache to force a fresh lookup that bypasses (and does not
        update) the table.

    .PARAMETER Sid
        The SID string to resolve, e.g. "S-1-5-32-544".

    .PARAMETER NoCache
        Skip the global cache for this lookup. Result is neither read
        from nor written to the cache.

    .OUTPUTS
        [string] NT-account name (e.g. "BUILTIN\Administrators"), or $null
        when resolution fails.

    .EXAMPLE
        Resolve-ADSidName -Sid 'S-1-5-32-544'
        # -> 'BUILTIN\Administrators'

    .EXAMPLE
        $aSids | Resolve-ADSidName
        # Pipelines a batch of SIDs; cache hits short-circuit repeated
        # lookups for shared groups.

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-05-26) - Initial version. Promoted from a nested
                             helper inside Get-ADGroupPolicyLocalGroupMembership
                             so the per-export SID cache is shared across
                             every consumer (GptTmpl.inf [Privilege Rights]
                             URA values, Restricted Groups members,
                             GPP local groups).
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Sid,

        [switch]$NoCache
    )

    Process {
        # Lazy-init at first use. Survives Import-Module -Force because
        # it lives in the global scope, not the module's.
        if ($null -eq $global:ADSidNameCache) {
            $global:ADSidNameCache = @{}
        }

        if (-not $NoCache -and $global:ADSidNameCache.ContainsKey($Sid)) {
            return $global:ADSidNameCache[$Sid]
        }

        $sName = $null
        try {
            $oSid  = New-Object System.Security.Principal.SecurityIdentifier($Sid)
            $sName = $oSid.Translate([System.Security.Principal.NTAccount]).Value
        } catch {
            $sName = $null
        }

        if (-not $NoCache) { $global:ADSidNameCache[$Sid] = $sName }
        return $sName
    }
}
