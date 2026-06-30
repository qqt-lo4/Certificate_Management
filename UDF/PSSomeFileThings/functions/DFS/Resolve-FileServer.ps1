function Resolve-FileServer {
    <#
    .SYNOPSIS
        Resolves a list of share / namespace UNC paths to a hashtable
        mapping each resolved folder to the file server actually
        hosting it.

    .DESCRIPTION
        For each input UNC path:

          - The UNC server itself is always recorded under a key equal
            to the original input path. It is either the DFS namespace
            host (a Windows server worth scoping in its own right) or
            the direct filer hosting the share.
          - A DFS resolution is then attempted via Get-DFSFolders
            against that same server. When the namespace returns
            folders (one path with a wildcard typically fans out to N
            target folders), each resolved folder enters the map under
            its DFS path key, pointing at the .targetServer that
            actually serves it. Different folders under the same
            namespace can point at different filers - the map captures
            the full fan-out.
          - When the probe returns nothing or throws, the input UNC
            itself is the only entry (treated as a direct filer).

        Warnings written by Get-DFSFolders - both from the local
        invocation and from the remote DFSN scriptblock - are
        suppressed via -WarningAction SilentlyContinue. The cmdlet
        forwards its $WarningPreference into the remote scriptblock
        explicitly, so the call-site preference actually mutes the
        "Cannot enumerate" warning that PS 5.1 would otherwise leak
        across the remoting boundary. Failures still go to Verbose
        for diagnostics.

        File-server values are normalised to upper-case short names
        (FQDN suffixes stripped, casing uniformised) so mixed forms
        ("frfil02" / "FRFIL02" / "frfil02.example.com" - DFS emits
        whatever case was used at link creation) collapse to a single
        canonical "FRFIL02" on the value side. Callers wanting just
        the unique server-list flatten with `.Values | Sort-Object -Unique`.

        Designed as a generic helper: callers decide whether to cache
        the result in a global - this function itself is pure
        (input -> output, no side effects).

    .PARAMETER Path
        One or more UNC paths in the form \\server\share[\subpath].
        Wildcards in the last segment are forwarded as-is to
        Get-DFSFolders (supported for DFS namespaces only).

    .PARAMETER Credential
        Credential for the Get-DFSFolders Invoke-Command call. When
        omitted, the resolution runs as the current identity.

    .OUTPUTS
        [hashtable] - keys are resolved folder paths (DFS folder UNCs
        for namespace expansions, or the original input UNC for
        direct filers / unresolved entries); values are the file
        server short names actually hosting each folder.

    .EXAMPLE
        # Direct filer + DFS expansion: each DFS folder lands under
        # its own key with the resolved targetServer as the value.
        $hMap = Resolve-FileServer -Path @(
            '\\FILER01.example.com\share$\*'
            '\\DFS01.example.com\namespace\folder*'
        ) -Credential $cred

        # Audit-style listing of "what's on which filer":
        $hMap.GetEnumerator() | Sort-Object Value, Name

        # Flat list of unique file servers:
        @($hMap.Values | Sort-Object -Unique)

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-06-10, Loic Ade) - Initial version. Extracted from
                             the inline DFS / Filer walker in
                             Export-FilerAccess so any caller needing
                             the resolved folder-to-server map of a
                             list of share paths can get it in one
                             call. Return shape is a hashtable keyed
                             by folder path - carries the per-folder
                             targetServer mapping that a flat
                             unique-list would collapse away. The
                             flat list is one ".Values |
                             Sort-Object -Unique" away.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string[]]$Path,

        [PSCredential]$Credential
    )
    Process {
        $hCredParam = @{}
        if ($Credential) { $hCredParam['Credential'] = $Credential }

        # Plain hashtable - keys may collide across DFS namespaces if
        # two inputs both expand to the same folder, last writer wins.
        # In practice the share definitions don't overlap so this is
        # benign; if it ever matters, the caller can run separate
        # resolutions and merge them.
        $hMap = @{}

        # Helper: trim FQDN suffix and uppercase. Filers downstream
        # (BeyondTrust, Qualys, AD) use short upper-case names;
        # mixing forms ("frfil02" / "FRFIL02" / "frfil02.example.com",
        # all emitted from the same DFS namespace depending on the
        # casing used at link creation) would bloat the dedup the
        # caller does on .Values and look ugly in audit output.
        $sShorten = {
            param([string]$s)
            $sShort = if ($s -match '^([^.]+)') { $Matches[1] } else { $s }
            $sShort.ToUpper()
        }

        foreach ($sPath in $Path) {
            if (-not $sPath) { continue }

            # Extract the server segment from the UNC. Always recorded:
            # it is either the DFS namespace host (a Windows server
            # worth scoping for AD / Qualys / Cortex) or the direct
            # filer hosting the share.
            if ($sPath -notmatch '^\\\\([^\\]+)\\') {
                Write-Warning "Resolve-FileServer : path '$sPath' is not a valid UNC - skipped."
                continue
            }
            $sServer = & $sShorten $Matches[1]

            # Probe for DFS resolution. A real namespace returns at
            # least one folder; a plain file share returns nothing or
            # trips a remote error. -WarningAction SilentlyContinue
            # mutes both the local "Cannot connect" and the remote
            # "Cannot enumerate / Get-DfsnFolder not recognised"
            # warnings, the latter only because Get-DFSFolders now
            # forwards $WarningPreference into its Invoke-Command
            # scriptblock - the call-site -WarningAction alone is
            # otherwise dropped at the remoting boundary on PS 5.1.
            $aDFS = @()
            try {
                $aDFS = @(Get-DFSFolders -Path $sPath -ComputerName $sServer @hCredParam -WarningAction SilentlyContinue)
            } catch {
                Write-Verbose "Resolve-FileServer : DFS probe failed for '$sPath' ($($_.Exception.Message)) - treated as direct filer."
            }

            if ($aDFS.Count -gt 0) {
                # DFS namespace: every resolved folder gets its own
                # entry. The namespace host itself is also recorded
                # (under the input path key) - it's a real Windows
                # server worth scoping even though it doesn't host
                # the data.
                $hMap[$sPath] = $sServer
                foreach ($oFolder in $aDFS) {
                    if (-not $oFolder.targetServer) { continue }
                    $sKey = if ($oFolder.dfsPath) { [string]$oFolder.dfsPath } else { "$sPath#$($oFolder.folderName)" }
                    $hMap[$sKey] = & $sShorten ([string]$oFolder.targetServer)
                }
            } else {
                # Direct filer (or DFS resolution failed).
                $hMap[$sPath] = $sServer
            }
        }

        return $hMap
    }
}
