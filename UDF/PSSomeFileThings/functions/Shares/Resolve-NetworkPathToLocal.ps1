function Resolve-NetworkPathToLocal {
    <#
    .SYNOPSIS
        Resolves a UNC network path to its real physical folder on a file server.

    .DESCRIPTION
        Walks a UNC path and returns the underlying server + local filesystem
        path. DFS resolution is delegated to the DFS namespace server via
        Invoke-Command: the target server runs the native RSAT DFS cmdlets
        (Get-DfsnFolder / Get-DfsnFolderTarget) which already handle every
        namespace shape (domain-based, standalone, FQDN vs short name) and
        wildcards in the last path segment.

        For each resolved DFS target — or, when the input is not a DFS path,
        for the input UNC itself — the function opens a CIM session on the
        target file server, reads the share's local root via Get-SmbShare
        and joins the remaining subfolder to return the real on-disk path.

        Wildcards in the last segment are expanded. When the wildcarded
        segment resolves to a plain directory (not a DFS link), the matching
        children are enumerated via the SMB client and each match is
        resolved independently (it may itself be a DFS link or a regular
        folder).

    .PARAMETER Path
        UNC path to resolve. Accepts pipeline input. May contain a wildcard
        in the last segment (e.g. "\\server\share\folder\dump*").

    .PARAMETER DFSServer
        Optional DFS namespace server used for DFS resolution. Defaults to
        the host portion of the input UNC, which works when the caller
        rooted the path on a DFS namespace server. Required when the path
        is rooted on a domain name (e.g. "\\contoso.com\ns\...").

    .PARAMETER Credential
        Credentials for the Invoke-Command session against the DFS server
        AND for the CIM session against the final target file server.

    .OUTPUTS
        PSCustomObject with:
            NetworkPath : the original input (or the expanded child UNC)
            Server      : FQDN / short name of the target file server
            Share       : share name on that server
            LocalPath   : real on-disk path on the server
            IsDFS       : $true when the path was resolved through DFS

    .EXAMPLE
        Resolve-NetworkPathToLocal -Path "\\FRDFS01\intersites_dga\securise\dump*" -Credential $cred

    .EXAMPLE
        "\\FRASN08.stago.grp\international$\Project" | Resolve-NetworkPathToLocal -Credential $cred

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-04-13) - Initial version (remoted DFS resolution via
                             Invoke-Command on the DFS namespace server)
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Path,

        [string]$DFSServer,

        [PSCredential]$Credential
    )

    Begin {
        # Helper: split a UNC path into server / share / remainder
        function Split-UncPath {
            Param([string]$UncPath)
            $sTrim = $UncPath.TrimStart('\')
            $aParts = $sTrim -split '\\', 3
            if ($aParts.Count -lt 2) { return $null }
            [PSCustomObject]@{
                Server    = $aParts[0]
                Share     = $aParts[1]
                Remainder = if ($aParts.Count -ge 3) { $aParts[2] } else { '' }
            }
        }

        # Helper: resolve a single \\server\share\remainder to a local path
        # on the target server via a CIM session + Get-SmbShare.
        function Resolve-UncToLocal {
            Param(
                [Parameter(Mandatory)][string]$Unc,
                [PSCredential]$Cred
            )
            $oParts = Split-UncPath -UncPath $Unc
            if (-not $oParts) { throw "Cannot parse '$Unc'" }

            $hSessionParams = @{ ComputerName = $oParts.Server; ErrorAction = 'Stop' }
            if ($Cred) { $hSessionParams['Credential'] = $Cred }

            $oSession = $null
            try {
                $oSession = New-CimSession @hSessionParams
                $oShare = Get-SmbShare -Name $oParts.Share -CimSession $oSession -ErrorAction Stop
                $sLocalRoot = $oShare.Path
            } finally {
                if ($oSession) { Remove-CimSession $oSession -ErrorAction SilentlyContinue }
            }

            # Plain string concatenation: Join-Path would try to resolve the
            # drive letter of the remote local root (e.g. "N:\...") in the
            # local PS session and fail with DriveNotFound.
            $sLocalPath = if ($oParts.Remainder) {
                $sLocalRoot.TrimEnd('\') + '\' + $oParts.Remainder.TrimStart('\')
            } else {
                $sLocalRoot
            }

            [PSCustomObject]@{
                Server    = $oParts.Server
                Share     = $oParts.Share
                LocalPath = $sLocalPath
            }
        }
    }

    Process {
        $sInput = $Path.Trim() -replace '/', '\'
        if ($sInput -notmatch '^\\\\[^\\]+\\[^\\]+') {
            throw "Resolve-NetworkPathToLocal: not a UNC path - '$Path'"
        }

        # Pick the DFS namespace server to query. Default to the host
        # portion of the input path (typical when the caller rooted the
        # path on the namespace server itself).
        $sDFSServer = if ($DFSServer) { $DFSServer } else { ($sInput.TrimStart('\') -split '\\', 2)[0] }

        $hRemoteParams = @{ ComputerName = $sDFSServer; ErrorAction = 'Stop' }
        if ($Credential) { $hRemoteParams['Credential'] = $Credential }

        # --- Remote DFS enumeration -----------------------------------------
        # Run Get-DfsnFolder / Get-DfsnFolderTarget on the DFS server. The
        # cmdlet supports wildcards natively in the last segment and returns
        # one row per (folder, target) pair. Returns an empty array when
        # the path is not a DFS link (we fall back to SMB enumeration below).
        $aDfsRows = @()
        try {
            $aDfsRows = @(Invoke-Command @hRemoteParams -ScriptBlock {
                Param($sPattern)
                try {
                    $aFolders = @(Get-DfsnFolder -Path $sPattern -ErrorAction Stop)
                } catch {
                    return @()
                }
                $aOut = @()
                foreach ($oFolder in $aFolders) {
                    $aTargets = @()
                    try {
                        $aTargets = @(Get-DfsnFolderTarget -Path $oFolder.Path -ErrorAction Stop)
                    } catch {}
                    if ($aTargets.Count -eq 0) { continue }
                    # Prefer Online targets
                    $oPicked = $aTargets | Where-Object { $_.State -eq 'Online' } | Select-Object -First 1
                    if (-not $oPicked) { $oPicked = $aTargets[0] }
                    $aOut += [PSCustomObject]@{
                        DfsPath    = $oFolder.Path
                        TargetPath = $oPicked.TargetPath
                    }
                }
                return $aOut
            } -ArgumentList $sInput)
        } catch {
            Write-Verbose "Resolve-NetworkPathToLocal: remote DFS query on $sDFSServer failed - $_"
        }

        if ($aDfsRows.Count -gt 0) {
            # DFS results (may be several if the input was a wildcard)
            foreach ($oRow in $aDfsRows) {
                try {
                    $oLocal = Resolve-UncToLocal -Unc $oRow.TargetPath -Cred $Credential
                    [PSCustomObject][ordered]@{
                        NetworkPath = $oRow.DfsPath
                        Server      = $oLocal.Server
                        Share       = $oLocal.Share
                        LocalPath   = $oLocal.LocalPath
                        IsDFS       = $true
                    }
                } catch {
                    Write-Warning "Resolve-NetworkPathToLocal: '$($oRow.DfsPath)' -> '$($oRow.TargetPath)' - $_"
                }
            }
            return
        }

        # --- No DFS match: handle wildcard via SMB enumeration --------------
        # When the last segment contains a wildcard but the path is not a
        # DFS folder, enumerate the matching children via the SMB client
        # and recurse on each. A single child may still be a DFS link
        # (which the remote query above will catch on the recursive call).
        if ($sInput -match '^(.+?)\\([^\\]*[\*\?][^\\]*)$') {
            $sParent  = $Matches[1]
            $sPattern = $Matches[2]

            $aChildren = @()
            try {
                $aChildren = @(Get-ChildItem -LiteralPath $sParent -Directory -Force -ErrorAction Stop |
                    Where-Object { $_.Name -like $sPattern })
            } catch {
                throw "Resolve-NetworkPathToLocal: cannot enumerate '$sParent' - $_"
            }

            if ($aChildren.Count -eq 0) {
                Write-Verbose "Resolve-NetworkPathToLocal: no child under '$sParent' matches '$sPattern'"
                return
            }

            foreach ($oChild in $aChildren) {
                $sChildUnc = Join-Path $sParent $oChild.Name
                try {
                    # Recurse so child DFS links are resolved too
                    Resolve-NetworkPathToLocal -Path $sChildUnc -DFSServer $sDFSServer -Credential $Credential
                } catch {
                    Write-Warning "Resolve-NetworkPathToLocal: '$sChildUnc' - $_"
                }
            }
            return
        }

        # --- No wildcard, no DFS: plain UNC → local path ---------------------
        try {
            $oLocal = Resolve-UncToLocal -Unc $sInput -Cred $Credential
            [PSCustomObject][ordered]@{
                NetworkPath = $Path
                Server      = $oLocal.Server
                Share       = $oLocal.Share
                LocalPath   = $oLocal.LocalPath
                IsDFS       = $false
            }
        } catch {
            throw "Resolve-NetworkPathToLocal: '$sInput' - $_"
        }
    }
}
