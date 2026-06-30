function Get-SharePermissions {
    <#
    .SYNOPSIS
        Retrieves detailed NTFS permissions for specific share paths.

    .DESCRIPTION
        For each UNC path provided, connects to the hosting server via Invoke-Command
        and retrieves NTFS ACL entries. Useful for auditing specific shares or subfolders.
        Requires admin access on the target server.

    .PARAMETER UNCPath
        One or more UNC paths (e.g. "\\server\share" or "\\server\share\subfolder").

    .PARAMETER Credential
        Credentials for remote execution.

    .PARAMETER ExcludeInherited
        If specified, excludes inherited ACL entries.

    .OUTPUTS
        [PSCustomObject[]] ACL entries with uncPath, server, localPath,
        identityReference, fileSystemRights, accessControlType, isInherited.

    .EXAMPLE
        Get-SharePermissions -UNCPath "\\FILER01\Data\Finance"

    .EXAMPLE
        Get-SharePermissions -UNCPath "\\FILER01\Data", "\\FILER02\Home" -Credential $cred -ExcludeInherited

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-04-01) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]$UNCPath,

        [PSCredential]$Credential,

        [switch]$ExcludeInherited
    )

    Begin {
        $aResults = @()
        $hRemoteParams = @{}
        if ($Credential) { $hRemoteParams['Credential'] = $Credential }
    }

    Process {
        foreach ($sUNC in $UNCPath) {
            # Extract server from UNC
            if ($sUNC -notmatch '^\\\\([^\\]+)\\(.+)$') {
                Write-Warning "Get-SharePermissions: Invalid UNC path '$sUNC'"
                continue
            }
            $sServer = $Matches[1]

            Write-Verbose "Getting ACL for: $sUNC (server: $sServer)"

            try {
                $aACL = Invoke-Command -ComputerName $sServer @hRemoteParams -ScriptBlock {
                    param($UNCPath)
                    # Convert UNC to local path
                    if ($UNCPath -match "^\\\\[^\\]+\\([^\\]+)(.*)$") {
                        $sShareName = $Matches[1]
                        $sSubPath = $Matches[2]
                        $oShare = Get-SmbShare -Name $sShareName -ErrorAction SilentlyContinue
                        if ($oShare) {
                            $sLocalPath = $oShare.Path + $sSubPath
                        } else {
                            throw "Share '$sShareName' not found on $env:COMPUTERNAME"
                        }
                    } else {
                        throw "Cannot parse UNC path: $UNCPath"
                    }

                    $oACL = Get-Acl -Path $sLocalPath -ErrorAction Stop
                    $oACL.Access | ForEach-Object {
                        [PSCustomObject]@{
                            LocalPath          = $sLocalPath
                            IdentityReference  = $_.IdentityReference.ToString()
                            FileSystemRights   = $_.FileSystemRights.ToString()
                            AccessControlType  = $_.AccessControlType.ToString()
                            IsInherited        = $_.IsInherited
                            InheritanceFlags   = $_.InheritanceFlags.ToString()
                            PropagationFlags   = $_.PropagationFlags.ToString()
                        }
                    }
                } -ArgumentList $sUNC

                foreach ($oACE in $aACL) {
                    if ($ExcludeInherited -and $oACE.IsInherited) { continue }

                    $aResults += [PSCustomObject][ordered]@{
                        uncPath            = $sUNC
                        server             = $sServer
                        localPath          = $oACE.LocalPath
                        identityReference  = $oACE.IdentityReference
                        fileSystemRights   = $oACE.FileSystemRights
                        accessControlType  = $oACE.AccessControlType
                        isInherited        = $oACE.IsInherited
                        inheritanceFlags   = $oACE.InheritanceFlags
                        propagationFlags   = $oACE.PropagationFlags
                    }
                }
            } catch {
                Write-Warning "Get-SharePermissions: Cannot get ACL on '$sUNC' via $sServer - $_"
            }
        }
    }

    End {
        return $aResults
    }
}
