function Get-FileServerShares {
    <#
    .SYNOPSIS
        Lists SMB shares on a file server with their permissions.

    .DESCRIPTION
        Connects to a remote file server (via an existing -Session or a fresh -ComputerName
        connection) and retrieves its SMB shares with share-level permissions and optionally
        NTFS root permissions. Requires admin access on the target server.

        By default the share list comes from Get-SmbShare. That cmdlet can HIDE shares from an
        account that lacks share-level visibility (or fail outright), so two opt-in switches add
        permission-tolerant enumeration sources and MERGE them by share name:

            -IncludeRegistryShares  reads HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\
                                    Shares, the authoritative list of the manually-created
                                    persistent shares (admin/default shares are not there). It
                                    only needs registry read, so it surfaces shares Get-SmbShare
                                    won't show to a caller without share visibility.
            -IncludeWmiShares       enumerates Win32_Share (a different provider path).

        When either switch is used, each result gains a 'Source' field ("SMB", "Registry",
        "WMI", or a combination like "SMB+Registry") so the report shows which shares were only
        found via the alternative source. Default output shape is unchanged when no switch is set.

    .PARAMETER ComputerName
        One or more file server names to query. Mutually exclusive with -Session.

    .PARAMETER Credential
        Credentials for remote execution (with -ComputerName).

    .PARAMETER Session
        Existing PSSession(s) to reuse. Mutually exclusive with -ComputerName.

    .PARAMETER IncludeNTFS
        If specified, also retrieves NTFS permissions on each share's root folder.

    .PARAMETER ExcludeSystem
        If specified, excludes default system shares (ADMIN$, C$, IPC$, print$, etc.).
        Default: $true.

    .PARAMETER IncludeRegistryShares
        Also enumerate persistent shares from the LanmanServer registry key and merge them in.
        Permission-tolerant; recommended when Get-SmbShare misses configured shares.

    .PARAMETER IncludeWmiShares
        Also enumerate shares via Win32_Share (CIM) and merge them in.

    .OUTPUTS
        [PSCustomObject[]] Share information: server, name, path, description, shareState,
        sharePermissions, optionally source (with a merge switch) and ntfsPermissions.

    .EXAMPLE
        Get-FileServerShares -ComputerName "FILER01"

    .EXAMPLE
        Get-FileServerShares -Session $oSession -IncludeRegistryShares -IncludeWmiShares -IncludeNTFS

    .NOTES
        Author  : Loic Ade
        Version : 1.1.0

        1.1.0 (2026-08-20) - Add -Session (reuse an existing PSSession) and two opt-in
            enumeration sources merged by name: -IncludeRegistryShares (LanmanServer registry,
            permission-tolerant) and -IncludeWmiShares (Win32_Share). A 'source' field is added
            when a merge switch is used. ComputerName is no longer mandatory (Session alternative).
            With -IncludeRegistryShares, share permissions also fall back to the binary security
            descriptors under Shares\Security - parsed into Account/Right/Type text - when
            Get-SmbShareAccess is blocked, so hidden shares still report their ACL. NTFS root
            permissions are now read with -LiteralPath and no Test-Path guard that
            false-negatives on traverse-denied parents, include inherited ACEs marked as such,
            and a read failure is surfaced as an "NTFS read failed" marker instead of a blank.
            A ntfsPrincipals field (distinct account names only) is emitted alongside the full
            ntfsPermissions, for a lightweight column when the rights live in a detail table.
            The folder owner is captured too (owner field) so a CREATOR OWNER ACE can be
            resolved to the real principal downstream.
        1.0.0 (2026-04-01) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline)]
        [string[]]$ComputerName,

        [PSCredential]$Credential,

        [System.Management.Automation.Runspaces.PSSession[]]$Session,

        [switch]$IncludeNTFS,

        [bool]$ExcludeSystem = $true,

        [switch]$IncludeRegistryShares,

        [switch]$IncludeWmiShares
    )

    Begin {
        if ($Session -and $ComputerName) {
            throw "Incompatible arguments : you can't use -Session and -ComputerName at the same time"
        }
        $aResults = @()

        # Runs ON the server. Builds a name-keyed merge of every enabled source
        # so a share hidden from one provider still appears via another, then
        # resolves permissions per share (best effort).
        $oScriptBlock = {
            param($bExcludeSystem, $bIncludeNTFS, $bRegistry, $bWmi)

            $aSystemShares = @('ADMIN$', 'IPC$', 'print$')
            $hShares = [ordered]@{}

            $fnEnsure = {
                param($sName)
                if (-not $hShares.Contains($sName)) {
                    $hShares[$sName] = [PSCustomObject]@{
                        Name = $sName; Path = $null; Description = $null; ShareState = $null
                        Sources = [System.Collections.Generic.List[string]]::new()
                    }
                }
                $hShares[$sName]
            }

            # 1. Get-SmbShare (default) - richest metadata, incl. system shares.
            try {
                foreach ($o in (Get-SmbShare -ErrorAction Stop)) {
                    $r = & $fnEnsure $o.Name
                    $r.Path = $o.Path; $r.Description = $o.Description; $r.ShareState = "$($o.ShareState)"
                    if ($r.Sources -notcontains 'SMB') { $r.Sources.Add('SMB') }
                }
            } catch {}

            # 2. Registry (persistent, manually-created shares; permission-tolerant).
            if ($bRegistry) {
                $sReg = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares'
                try {
                    $oKey = Get-Item -LiteralPath $sReg -ErrorAction Stop
                    foreach ($sVal in $oKey.GetValueNames()) {
                        if ([string]::IsNullOrEmpty($sVal)) { continue }  # skip (Default)
                        $h = @{}
                        foreach ($sLine in @($oKey.GetValue($sVal))) {
                            $iEq = "$sLine".IndexOf('=')
                            if ($iEq -gt 0) { $h[$sLine.Substring(0, $iEq)] = $sLine.Substring($iEq + 1) }
                        }
                        $sName = if ($h.ContainsKey('ShareName') -and $h['ShareName']) { $h['ShareName'] } else { $sVal }
                        $r = & $fnEnsure $sName
                        if (-not $r.Path -and $h.ContainsKey('Path')) { $r.Path = $h['Path'] }
                        if (-not $r.Description -and $h.ContainsKey('Remark')) { $r.Description = $h['Remark'] }
                        if ($r.Sources -notcontains 'Registry') { $r.Sources.Add('Registry') }
                    }
                } catch {}
            }

            # 3. Win32_Share (CIM) - a different provider path.
            if ($bWmi) {
                try {
                    foreach ($o in (Get-CimInstance Win32_Share -ErrorAction Stop)) {
                        $r = & $fnEnsure $o.Name
                        if (-not $r.Path -and $o.Path) { $r.Path = $o.Path }
                        if (-not $r.Description -and $o.Description) { $r.Description = $o.Description }
                        if ($r.Sources -notcontains 'WMI') { $r.Sources.Add('WMI') }
                    }
                } catch {}
            }

            # Share-level ACLs also live in the registry (Shares\Security: one
            # binary security descriptor per share). Read them so permissions
            # can still be reported when Get-SmbShareAccess is blocked for the
            # caller. Keyed by the raw registry value name (= share name).
            $hSd = @{}
            if ($bRegistry) {
                $sSecReg = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares\Security'
                try {
                    $oSecKey = Get-Item -LiteralPath $sSecReg -ErrorAction Stop
                    foreach ($sVal in $oSecKey.GetValueNames()) {
                        if ([string]::IsNullOrEmpty($sVal)) { continue }
                        $hSd[$sVal] = [byte[]]$oSecKey.GetValue($sVal)
                    }
                } catch {}
            }

            # Parse a self-relative share security descriptor into
            # "Account (Right/Type)" strings, matching the Get-SmbShareAccess
            # rendering. SID -> name resolves on the server (this scriptblock),
            # so local and domain principals both translate.
            $fnParseSd = {
                param([byte[]]$aBytes)
                $aOut = @()
                try {
                    $oSd = New-Object System.Security.AccessControl.RawSecurityDescriptor($aBytes, 0)
                    if ($null -eq $oSd.DiscretionaryAcl) { return @('Everyone (Full/Allow)') }  # null DACL = full access
                    foreach ($oAce in $oSd.DiscretionaryAcl) {
                        $oSid  = $oAce.SecurityIdentifier
                        $sAcct = try { $oSid.Translate([System.Security.Principal.NTAccount]).Value } catch { $oSid.Value }
                        $sType = switch ("$($oAce.AceType)") { 'AccessAllowed' { 'Allow' } 'AccessDenied' { 'Deny' } default { "$($oAce.AceType)" } }
                        $iMask = [int]$oAce.AccessMask
                        $sRight = switch ($iMask) {
                            2032127 { 'Full' }    # 0x1F01FF
                            1245631 { 'Change' }  # 0x1301BF
                            1179817 { 'Read' }    # 0x1200A9
                            default { '0x{0:X}' -f $iMask }
                        }
                        $aOut += "$sAcct ($sRight/$sType)"
                    }
                } catch {}
                $aOut
            }

            $aList = @($hShares.Values)
            if ($bExcludeSystem) {
                $aList = @($aList | Where-Object { $_.Name -notin $aSystemShares -and $_.Name -notmatch '^[A-Z]\$$' })
            }

            $bMulti = $bRegistry -or $bWmi
            $aList | ForEach-Object {
                $oShare = $_

                # Share-level permissions (best effort - may be blocked for a
                # registry-only share the caller can't open).
                $aSharePerms = @()
                try {
                    $aSharePerms = @(Get-SmbShareAccess -Name $oShare.Name -ErrorAction Stop | ForEach-Object {
                        "$($_.AccountName) ($($_.AccessRight)/$($_.AccessControlType))"
                    })
                } catch {}
                # Fallback: parse the share ACL straight from the registry SD
                # when the SMB provider returned nothing (blocked, or the share
                # is only visible via the registry enumeration).
                if ($aSharePerms.Count -eq 0 -and $hSd.ContainsKey($oShare.Name)) {
                    $aSharePerms = @(& $fnParseSd $hSd[$oShare.Name])
                }

                # NTFS permissions on the share root. Read directly with
                # -LiteralPath and NO Test-Path guard: a parent folder that
                # denies traverse makes Test-Path false-negative even when the
                # ACL itself is readable, silently blanking the cell. Any real
                # failure is surfaced as a marker instead of an empty cell, so
                # "access denied" is distinguishable from "no permissions".
                # Inherited ACEs are included (marked) - project folders often
                # rely entirely on inheritance, which the old filter dropped.
                # NTFSPerms keeps the full "Account (Rights/Type)[ inherited]"
                # rendering (the per-principal detail is parsed from it), while
                # NTFSNames is just the distinct principal list - a lightweight
                # summary for the Shares table, with the rights broken out below.
                $aNTFSPerms = @()
                $aNtfsNames = @()
                $sNtfsOwner = ''
                if ($bIncludeNTFS -and $oShare.Path) {
                    try {
                        $oACL = Get-Acl -LiteralPath $oShare.Path -ErrorAction Stop
                        # Owner resolves the real principal behind a CREATOR OWNER
                        # ACE (the account that owns the folder).
                        $sNtfsOwner = "$($oACL.Owner)"
                        $aAccess = @($oACL.Access)
                        $aNTFSPerms = @($aAccess | ForEach-Object {
                            $sInh = if ($_.IsInherited) { ' [inherited]' } else { '' }
                            "$($_.IdentityReference) ($($_.FileSystemRights)/$($_.AccessControlType))$sInh"
                        })
                        $aNtfsNames = @($aAccess | ForEach-Object { "$($_.IdentityReference)" } | Select-Object -Unique)
                    } catch {
                        $aNTFSPerms = @("[NTFS read failed: $($_.Exception.Message)]")
                        $aNtfsNames = $aNTFSPerms
                    }
                }

                $oOut = [ordered]@{
                    Name             = $oShare.Name
                    Path             = $oShare.Path
                    Description      = $oShare.Description
                    ShareState       = $oShare.ShareState
                    SharePermissions = ($aSharePerms -join '; ')
                }
                if ($bMulti) { $oOut['Source'] = ($oShare.Sources -join '+') }
                if ($bIncludeNTFS) {
                    $oOut['NTFSOwner']       = $sNtfsOwner
                    $oOut['NTFSPrincipals']  = ($aNtfsNames -join '; ')
                    $oOut['NTFSPermissions'] = ($aNTFSPerms -join '; ')
                }
                [PSCustomObject]$oOut
            }
        }
        $aArgs = @($ExcludeSystem, $IncludeNTFS.IsPresent, $IncludeRegistryShares.IsPresent, $IncludeWmiShares.IsPresent)
    }

    Process {
        # Build the (server label -> invoke params) list once per input.
        $aTargets = @()
        if ($Session) {
            foreach ($oSess in $Session) {
                $aTargets += @{ Label = $oSess.ComputerName; Remote = @{ Session = $oSess } }
            }
        } else {
            foreach ($sServer in $ComputerName) {
                $hRemote = @{ ComputerName = $sServer }
                if ($Credential) { $hRemote['Credential'] = $Credential }
                $aTargets += @{ Label = $sServer; Remote = $hRemote }
            }
        }

        foreach ($oTarget in $aTargets) {
            $sServer = $oTarget.Label
            $hRemote = $oTarget.Remote
            Write-Verbose "Querying shares on: $sServer"
            try {
                $aShares = Invoke-Command @hRemote -ScriptBlock $oScriptBlock -ArgumentList $aArgs

                foreach ($oShare in $aShares) {
                    $hObj = [ordered]@{
                        server           = $sServer
                        name             = $oShare.Name
                        path             = $oShare.Path
                        description      = $oShare.Description
                        shareState       = $oShare.ShareState
                        sharePermissions = $oShare.SharePermissions
                    }
                    if ($IncludeRegistryShares -or $IncludeWmiShares) { $hObj['source'] = $oShare.Source }
                    if ($IncludeNTFS) {
                        $hObj['owner']           = $oShare.NTFSOwner
                        $hObj['ntfsPrincipals']  = $oShare.NTFSPrincipals
                        $hObj['ntfsPermissions'] = $oShare.NTFSPermissions
                    }
                    $aResults += [PSCustomObject]$hObj
                }
            } catch {
                Write-Warning "Get-FileServerShares: Cannot query shares on '$sServer' - $_"
            }
        }
    }

    End {
        return $aResults
    }
}
