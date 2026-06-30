function Get-FilerFolderPermissions {
    <#
    .SYNOPSIS
        Retrieves NTFS permissions for folders on a file server.

    .DESCRIPTION
        Connects to the file server via Invoke-Command and retrieves NTFS ACL
        permissions using a known local path or by resolving a UNC target path.
        Requires admin access on the target file server.

    .PARAMETER FolderInfo
        One or more folder info objects with targetServer and either localPath
        or targetPath properties. Accepts pipeline input.

    .PARAMETER Credential
        Credentials for remote execution on the file server.

    .PARAMETER ExcludeInherited
        If specified, excludes inherited ACL entries.

    .OUTPUTS
        [PSCustomObject[]] ACL entries with folderName, targetServer, targetPath,
        identityReference, fileSystemRights, accessControlType, isInherited, inheritanceFlags.

    .EXAMPLE
        $folder = [PSCustomObject]@{ folderName = "Finance"; targetServer = "FILER01"; targetPath = "\\FILER01\data$\finance"; localPath = "D:\data\finance" }
        Get-FilerFolderPermissions -FolderInfo $folder -Credential $cred -ExcludeInherited

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-04-01) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$FolderInfo,

        [PSCredential]$Credential,

        [switch]$ExcludeInherited
    )

    Begin {
        $aResults = @()
        $hRemoteParams = @{}
        if ($Credential) { $hRemoteParams['Credential'] = $Credential }
    }

    Process {
        foreach ($oInfo in $FolderInfo) {
            $sServer = $oInfo.targetServer
            if (-not $sServer) {
                Write-Verbose "Skipping '$($oInfo.folderName)' - no target server"
                continue
            }

            # Determine path to use: localPath (already resolved) or targetPath (needs share resolution)
            $sLocalPath = $oInfo.localPath
            $sTargetPath = $oInfo.targetPath
            $bNeedsResolve = -not $sLocalPath

            Write-Verbose "Getting ACL: $(if ($sLocalPath) { $sLocalPath } else { $sTargetPath }) (server: $sServer)"

            try {
                $bExcl = $ExcludeInherited.IsPresent

                $aACL = Invoke-Command -ComputerName $sServer @hRemoteParams -ScriptBlock {
                    param($LocalPath, $TargetPath, $bNeedsResolve, $bExcludeInherited)

                    $sPath = $LocalPath
                    if ($bNeedsResolve -and $TargetPath) {
                        # Resolve UNC to local path via share
                        if ($TargetPath -match "^\\\\[^\\]+\\([^\\]+)(.*)$") {
                            $sShareName = $Matches[1]
                            $sSubPath = $Matches[2]
                            $oShare = Get-SmbShare -Name $sShareName -ErrorAction SilentlyContinue
                            if ($oShare) {
                                $sPath = $oShare.Path.TrimEnd('\') + $sSubPath
                            } else {
                                throw "Share '$sShareName' not found on $env:COMPUTERNAME"
                            }
                        } else {
                            throw "Cannot parse UNC path: $TargetPath"
                        }
                    }

                    if (-not $sPath) { throw "No path to check" }

                    $oACL = Get-Acl -Path $sPath -ErrorAction Stop
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
                } -ArgumentList $sLocalPath, $sTargetPath, $bNeedsResolve, $bExcl

                foreach ($oACE in $aACL) {
                    $aResults += [PSCustomObject][ordered]@{
                        folderName        = $oInfo.folderName
                        targetServer      = $sServer
                        targetPath        = $sTargetPath
                        identityReference = $oACE.IdentityReference
                        fileSystemRights  = $oACE.FileSystemRights
                        accessControlType = $oACE.AccessControlType
                        isInherited       = $oACE.IsInherited
                        inheritanceFlags  = $oACE.InheritanceFlags
                    }
                }
            } catch {
                Write-Warning "Get-FilerFolderPermissions: Cannot get ACL on '$(if ($sLocalPath) { $sLocalPath } else { $sTargetPath })' via $sServer - $_"
            }
        }
    }

    End {
        return $aResults
    }
}
