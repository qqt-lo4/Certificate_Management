function Add-SharePrincipalMembers {
    <#
    .SYNOPSIS
        Adds a 'members' column to share-access-detail rows by resolving each principal's
        direct members (or, for a user, its identity; for CREATOR OWNER, the folder owner).

    .DESCRIPTION
        Enriches the rows produced by Expand-SharePermissionDetail so the auditor can read what
        is actually behind each principal granted on a share. Best-effort, never throws:

            - Local groups (BUILTIN\*, SERVER\*) -> members from -LocalGroup, the local-group
              membership the server audit already collected (BUILTIN\Administrators is the
              machine's local Administrators group); no query is issued.
            - Domain principals (DOMAIN\name)    -> resolved on the calling host via
              Resolve-ADObject, then branched on objectClass:
                  group    -> its DIRECT members (Get-GroupMembers, no recursion),
                              shown as sAMAccountName (fallback: name);
                  user     -> "(user: <displayName>)" - so a user granted directly is
                              labelled as such instead of "not a group";
                  computer -> "(computer account)"; other -> "(<class>)".
            - CREATOR OWNER                       -> the folder's owner (resolved per row from
              the share's captured Owner), i.e. the real principal that ACE stands in for.
            - Well-known accounts (NT AUTHORITY\*, NT SERVICE\*, Everyone, application packages,
              raw SIDs)                          -> "(well-known)".
            - Unresolved / AD error               -> a "(...)" marker, never a blank.

        Distinct principals are cached (one lookup per group across all shares). CREATOR OWNER is
        NOT cached - its owner is per-share. Call once per server so BUILTIN\* and the owner
        resolve against the right machine.

    .PARAMETER Detail
        Share-access-detail rows (from Expand-SharePermissionDetail); each carries .principal,
        .server and .owner. Enriched in place with a 'members' property.

    .PARAMETER LocalGroup
        The server's local groups (from Get-LocalGroupMembership): objects with Name and
        Members. Used to resolve BUILTIN\* and SERVER\* principals without an AD query.

    .PARAMETER Server
        Optional AD server / domain override forwarded to the AD lookups.

    .PARAMETER Credential
        Optional credential for the AD queries. Omit to use the host's current identity.

    .PARAMETER PassThru
        Emit the (same, now-enriched) rows.

    .OUTPUTS
        None by default; with -PassThru the enriched rows.

    .EXAMPLE
        $detail = Expand-SharePermissionDetail -Share $shares
        Add-SharePrincipalMembers -Detail $detail -LocalGroup $localGroups

    .NOTES
        Author  : Loic Ade
        Version : 1.1.0

        1.1.0 (2026-08-21) - Resolve principals by objectClass via Resolve-ADObject: a user
            granted directly reads "(user: ...)" instead of "not an AD group"; CREATOR OWNER
            now resolves to the folder owner (per share).
        1.0.0 (2026-08-20) - Initial version.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        [object[]]$Detail,

        [AllowNull()]
        [object[]]$LocalGroup,

        [string]$Server,

        [System.Management.Automation.PSCredential]$Credential,

        [switch]$PassThru
    )

    Begin {
        $bHasAD = [bool](Get-Command Resolve-ADObject -ErrorAction SilentlyContinue) -and
                  [bool](Get-Command Get-GroupMembers -ErrorAction SilentlyContinue)

        # Forest NetBIOS -> DNS map, built once and reused across principals.
        $hNetBIOSMap = $null
        if ($bHasAD -and (Get-Command Get-ADDomainNetBIOSMap -ErrorAction SilentlyContinue)) {
            try {
                $hMapArgs = @{}
                if ($Credential) { $hMapArgs['Credential'] = $Credential }
                $hNetBIOSMap = Get-ADDomainNetBIOSMap @hMapArgs
            } catch {}
        }

        # Pseudo-account namespaces that are not enumerable groups. CREATOR OWNER is
        # handled per-row (its members are the folder owner), not here.
        $aWellKnownDomains = @('NT AUTHORITY', 'NT SERVICE', 'APPLICATION PACKAGE AUTHORITY',
                               'AUTORITE NT', 'AUTORITÉ DE PACKAGE D''APPLICATION')
        $aWellKnown = @('Everyone', 'Tout le monde', '(none resolved)')
        $aCreatorOwner = @('CREATOR OWNER', 'CREATEUR PROPRIETAIRE', 'CRÉATEUR PROPRIÉTAIRE')

        # Local-group lookup: short group name -> joined members.
        $hLocal = @{}
        foreach ($oG in $LocalGroup) {
            if ($oG -and $oG.Name) { $hLocal["$($oG.Name)".ToLower()] = "$($oG.Members)" }
        }

        $hCache = @{}
    }

    Process {
        # BUILTIN\* / SERVER\* resolve against this server's local groups.
        $sLocalServer = ''
        foreach ($oR in $Detail) { if ($oR -and $oR.server) { $sLocalServer = "$($oR.server)"; break } }

        $fnResolve = {
            param([string]$sPrincipal)
            if ($hCache.ContainsKey($sPrincipal)) { return $hCache[$sPrincipal] }

            $sDomain = ''
            $sName   = $sPrincipal
            if ($sPrincipal -match '^(?<dom>[^\\]+)\\(?<name>.+)$') {
                $sDomain = $Matches['dom']
                $sName   = $Matches['name']
            }
            $sDomU = $sDomain.ToUpper()
            $sKey  = $sName.ToLower()

            $bLocal = ($sDomU -eq 'BUILTIN') -or
                      ($sLocalServer -and $sDomU -eq $sLocalServer.ToUpper()) -or
                      ($sDomain -eq '' -and $hLocal.ContainsKey($sKey))

            if ($bLocal) {
                if ($hLocal.ContainsKey($sKey)) {
                    $sResult = if ($hLocal[$sKey]) { $hLocal[$sKey] } else { '(local group, empty)' }
                } else {
                    $sResult = '(local group, not collected)'
                }
            } elseif ($sPrincipal -in $aWellKnown -or $sPrincipal -match '^S-1-' -or $sDomU -in $aWellKnownDomains) {
                $sResult = '(well-known)'
            } elseif (-not $bHasAD) {
                $sResult = '(AD module not available)'
            } else {
                try {
                    $hR = @{ Identity = $sPrincipal; StrictPrefix = $true
                             Properties = @('objectclass', 'member', 'samaccountname', 'displayname', 'name') }
                    if ($hNetBIOSMap) { $hR['NetBIOSMap'] = $hNetBIOSMap }
                    if ($Credential)  { $hR['Credential'] = $Credential }
                    $oObj = Resolve-ADObject @hR -ErrorAction Stop | Select-Object -First 1

                    if (-not $oObj) {
                        $sResult = '(not found in AD)'
                    } else {
                        $aClass = @($oObj.objectclass) | ForEach-Object { "$_".ToLower() }
                        if ('group' -in $aClass) {
                            $aMembers = @(Get-GroupMembers -ADObject $oObj `
                                -ADObjectProperties @('samaccountname', 'name', 'displayname', 'objectclass'))
                            $aNames = @($aMembers | ForEach-Object {
                                if ($_.samaccountname) { "$($_.samaccountname)" }
                                elseif ($_.name)       { "$($_.name)" }
                                else                   { "$_" }
                            } | Where-Object { $_ } | Sort-Object -Unique)
                            $sResult = if ($aNames.Count) { $aNames -join '; ' } else { '(empty group)' }
                        } elseif ('user' -in $aClass) {
                            $sDisp = if ($oObj.displayname)     { "$($oObj.displayname)" }
                                     elseif ($oObj.samaccountname) { "$($oObj.samaccountname)" }
                                     else                          { $sName }
                            $sResult = "(user: $sDisp)"
                        } elseif ('computer' -in $aClass) {
                            $sResult = '(computer account)'
                        } else {
                            $sResult = "($($aClass[-1]))"
                        }
                    }
                } catch {
                    $sResult = "(unresolved: $($_.Exception.Message))"
                }
            }

            $hCache[$sPrincipal] = $sResult
            $sResult
        }

        foreach ($oRow in $Detail) {
            if (-not $oRow) { continue }
            $sP = "$($oRow.principal)"
            if ($sP -in $aCreatorOwner) {
                # Per share: the ACE stands in for whoever owns the folder.
                $sOwner = "$($oRow.owner)"
                $sMembers = if ($sOwner) { "owner: $sOwner" } else { '(owner unknown)' }
            } else {
                $sMembers = & $fnResolve $sP
            }
            $oRow | Add-Member -NotePropertyName 'members' -NotePropertyValue $sMembers -Force
        }

        if ($PassThru) { @($Detail) | Where-Object { $_ } }
    }
}
