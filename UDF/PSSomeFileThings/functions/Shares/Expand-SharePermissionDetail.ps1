function Expand-SharePermissionDetail {
    <#
    .SYNOPSIS
        Flattens Get-FileServerShares output into one row per (share, principal).

    .DESCRIPTION
        Pure data transformation (no remote call): takes the share objects produced by
        Get-FileServerShares and expands their joined sharePermissions / ntfsPermissions
        strings into a per-principal access matrix, so an auditor can read exactly which
        group/user has which share-level and NTFS right on each share.

        For every share, the principals from BOTH access lists are unioned; each output row
        carries that principal's share permission and NTFS permission side by side (blank on
        the side where the principal is absent). Entries are parsed from the
        "Account (Right/Type)[ [inherited]]" rendering the exporter emits; unparseable NTFS
        content (e.g. a "[NTFS read failed: ...]" marker) is carried through verbatim so the
        failure stays visible rather than looking like "no access".

        System / administrative shares (ADMIN$, IPC$, print$, drive letter $) are skipped by
        default - their ACLs are standard noise; pass -IncludeSystem to keep them.

    .PARAMETER Share
        Share objects from Get-FileServerShares (server, name, path, sharePermissions,
        ntfsPermissions, optionally source).

    .PARAMETER IncludeSystem
        Keep default administrative shares in the output.

    .OUTPUTS
        [PSCustomObject[]] One row per (share, principal): server, share, path, principal,
        sharePermission, ntfsPermission, source.

    .EXAMPLE
        $shares = Get-FileServerShares -Session $s -IncludeRegistryShares -IncludeNTFS
        Expand-SharePermissionDetail -Share $shares

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-08-20) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        [object[]]$Share,

        [switch]$IncludeSystem
    )

    Begin {
        $aOut = @()
        $aSystem = @('ADMIN$', 'IPC$', 'print$')
        # "Account (Rights/Type)" with an optional trailing " [inherited]". acct is
        # non-greedy up to the rights parenthesis; rights never contain '/' so the
        # Allow|Deny anchor at the end keeps the split unambiguous.
        $rxEntry = [regex]'^(?<acct>.*?)\s*\((?<rights>.*)/(?<type>Allow|Deny)\)(?<inh>\s*\[inherited\])?\s*$'

        $fnParse = {
            param([string]$sJoined, [bool]$bKeepInherited)
            $h = [ordered]@{}
            foreach ($sPart in @("$sJoined" -split ';\s*')) {
                $sPart = $sPart.Trim()
                if (-not $sPart) { continue }
                $m = $rxEntry.Match($sPart)
                if (-not $m.Success) { continue }
                $sAcct  = $m.Groups['acct'].Value.Trim()
                $sRight = "$($m.Groups['rights'].Value)/$($m.Groups['type'].Value)"
                if ($bKeepInherited -and $m.Groups['inh'].Value) { $sRight += ' [inherited]' }
                if (-not $h.Contains($sAcct)) { $h[$sAcct] = [System.Collections.Generic.List[string]]::new() }
                if ($h[$sAcct] -notcontains $sRight) { $h[$sAcct].Add($sRight) }
            }
            $h
        }
    }

    Process {
        foreach ($oShare in $Share) {
            if (-not $oShare) { continue }
            $sName = "$($oShare.name)"
            if (-not $IncludeSystem -and ($sName -in $aSystem -or $sName -match '^[A-Za-z]\$$')) { continue }

            $hShare = & $fnParse "$($oShare.sharePermissions)" $false

            $sNtfsRaw    = "$($oShare.ntfsPermissions)"
            $bNtfsFailed = $sNtfsRaw -match '^\s*\[NTFS read'
            $hNtfs       = if ($bNtfsFailed) { [ordered]@{} } else { & $fnParse $sNtfsRaw $true }

            $aPrincipals = @(@($hShare.Keys) + @($hNtfs.Keys) | Select-Object -Unique | Sort-Object)

            if ($aPrincipals.Count -eq 0) {
                # Nothing parsed - keep the share visible (e.g. NTFS read failed
                # and no share ACL) instead of silently dropping it.
                $aOut += [PSCustomObject][ordered]@{
                    server          = $oShare.server
                    share           = $sName
                    path            = $oShare.path
                    principal       = '(none resolved)'
                    sharePermission = ''
                    ntfsPermission  = if ($bNtfsFailed) { $sNtfsRaw } else { '' }
                    owner           = $oShare.owner
                    source          = $oShare.source
                }
                continue
            }

            foreach ($sP in $aPrincipals) {
                $sShareR = if ($hShare.Contains($sP)) { ($hShare[$sP] -join '; ') } else { '' }
                $sNtfsR  = if ($bNtfsFailed) { $sNtfsRaw } elseif ($hNtfs.Contains($sP)) { ($hNtfs[$sP] -join '; ') } else { '' }
                $aOut += [PSCustomObject][ordered]@{
                    server          = $oShare.server
                    share           = $sName
                    path            = $oShare.path
                    principal       = $sP
                    sharePermission = $sShareR
                    ntfsPermission  = $sNtfsR
                    # Carried through for CREATOR OWNER resolution (the folder
                    # owner is the real principal behind that ACE).
                    owner           = $oShare.owner
                    source          = $oShare.source
                }
            }
        }
    }

    End { return $aOut }
}
