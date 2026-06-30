function Get-DFSFolderPermissions {
    <#
    .SYNOPSIS
        Retrieves NTFS permissions for DFS folder targets.

    .DESCRIPTION
        For each DFS folder info object (from Get-DFSFolders), connects to the target
        file server via Invoke-Command and retrieves NTFS ACL permissions by resolving
        the UNC target path to a local path on the server.

    .PARAMETER DFSFolderInfo
        One or more objects from Get-DFSFolders (with targetPath and targetServer properties).
        Accepts pipeline input.

    .PARAMETER Credential
        Credentials for remote execution on file servers.

    .PARAMETER ExcludeInherited
        If specified, excludes inherited ACL entries.

    .OUTPUTS
        [PSCustomObject[]] ACL entries with dfsPath, folderName, targetServer, targetPath,
        identityReference, fileSystemRights, accessControlType, isInherited, inheritanceFlags.

    .EXAMPLE
        Get-DFSFolders -Path "\\contoso\shares\*" -ComputerName "DFS01" -Credential $cred |
            Get-DFSFolderPermissions -Credential $cred -ExcludeInherited

    .NOTES
        Author  : Loic Ade
        Version : 3.0.0

        3.0.0 (2026-04-01) - Fix double backslash in local path resolution
        2.0.0 (2026-04-01) - Invoke-Command on target file servers
        1.0.0 (2026-04-01) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$DFSFolderInfo,

        [PSCredential]$Credential,

        [switch]$ExcludeInherited
    )

    Begin {
        $aResults = @()
        $hRemoteParams = @{}
        if ($Credential) { $hRemoteParams['Credential'] = $Credential }
    }

    Process {
        foreach ($oInfo in $DFSFolderInfo) {
            $sTargetServer = $oInfo.targetServer
            $sTargetPath = $oInfo.targetPath

            if (-not $sTargetServer -or -not $sTargetPath) {
                Write-Verbose "Skipping '$($oInfo.dfsPath)' - no target resolved"
                continue
            }

            Write-Verbose "Getting ACL: $sTargetPath (server: $sTargetServer)"

            try {
                $bExcl = $ExcludeInherited.IsPresent

                $aACL = Invoke-Command -ComputerName $sTargetServer @hRemoteParams -ScriptBlock {
                    param($TargetPath, $bExcludeInherited)
                    # Parse UNC: \\server\share\sub\path
                    if ($TargetPath -match "^\\\\[^\\]+\\([^\\]+)(.*)$") {
                        $sShareName = $Matches[1]
                        $sSubPath = $Matches[2]
                        $oShare = Get-SmbShare -Name $sShareName -ErrorAction SilentlyContinue
                        if ($oShare) {
                            # Join share path + sub path, avoiding double backslash
                            $sLocalPath = $oShare.Path.TrimEnd('\') + $sSubPath
                        } else {
                            throw "Share '$sShareName' not found on $env:COMPUTERNAME"
                        }
                    } else {
                        throw "Cannot parse UNC path: $TargetPath"
                    }

                    $oACL = Get-Acl -Path $sLocalPath -ErrorAction Stop
                    $oACL.Access | Where-Object {
                        -not $bExcludeInherited -or -not $_.IsInherited
                    } | ForEach-Object {
                        [PSCustomObject]@{
                            IdentityReference = $_.IdentityReference.ToString()
                            FileSystemRights  = $_.FileSystemRights.ToString()
                            AccessControlType = $_.AccessControlType.ToString()
                            IsInherited       = $_.IsInherited
                            InheritanceFlags  = $_.InheritanceFlags.ToString()
                        }
                    }
                } -ArgumentList $sTargetPath, $bExcl

                foreach ($oACE in $aACL) {
                    $aResults += [PSCustomObject][ordered]@{
                        dfsPath           = $oInfo.dfsPath
                        folderName        = $oInfo.folderName
                        targetServer      = $sTargetServer
                        targetPath        = $sTargetPath
                        identityReference = $oACE.IdentityReference
                        fileSystemRights  = $oACE.FileSystemRights
                        accessControlType = $oACE.AccessControlType
                        isInherited       = $oACE.IsInherited
                        inheritanceFlags  = $oACE.InheritanceFlags
                    }
                }
            } catch {
                Write-Warning "Get-DFSFolderPermissions: Cannot get ACL on '$sTargetPath' via $sTargetServer - $_"
            }
        }
    }

    End {
        return $aResults
    }
}
