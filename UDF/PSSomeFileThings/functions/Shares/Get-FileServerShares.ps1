function Get-FileServerShares {
    <#
    .SYNOPSIS
        Lists SMB shares on a file server with their permissions.

    .DESCRIPTION
        Connects to a remote file server via Invoke-Command and retrieves all SMB shares
        with their share-level permissions and optionally NTFS root permissions.
        Requires admin access on the target server.

    .PARAMETER ComputerName
        One or more file server names to query.

    .PARAMETER Credential
        Credentials for remote execution.

    .PARAMETER IncludeNTFS
        If specified, also retrieves NTFS permissions on each share's root folder.

    .PARAMETER ExcludeSystem
        If specified, excludes default system shares (ADMIN$, C$, IPC$, etc.).
        Default: $true.

    .OUTPUTS
        [PSCustomObject[]] Share information with server, name, path, description,
        sharePermissions, and optionally ntfsPermissions.

    .EXAMPLE
        Get-FileServerShares -ComputerName "FILER01"

    .EXAMPLE
        Get-FileServerShares -ComputerName "FILER01", "FILER02" -Credential $cred -IncludeNTFS

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-04-01) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string[]]$ComputerName,

        [PSCredential]$Credential,

        [switch]$IncludeNTFS,

        [bool]$ExcludeSystem = $true
    )

    Begin {
        $aResults = @()
        $hRemoteParams = @{}
        if ($Credential) { $hRemoteParams['Credential'] = $Credential }
    }

    Process {
        foreach ($sServer in $ComputerName) {
            Write-Verbose "Querying shares on: $sServer"

            try {
                $aShares = Invoke-Command -ComputerName $sServer @hRemoteParams -ScriptBlock {
                    param($bExcludeSystem, $bIncludeNTFS)

                    $aSystemShares = @('ADMIN$', 'IPC$', 'print$')
                    $aShares = Get-SmbShare -ErrorAction Stop

                    if ($bExcludeSystem) {
                        $aShares = $aShares | Where-Object {
                            $_.Name -notin $aSystemShares -and $_.Name -notmatch '^[A-Z]\$$'
                        }
                    }

                    $aShares | ForEach-Object {
                        $oShare = $_

                        # Share-level permissions
                        $aSharePerms = @()
                        try {
                            $aSharePerms = @(Get-SmbShareAccess -Name $oShare.Name -ErrorAction Stop | ForEach-Object {
                                "$($_.AccountName) ($($_.AccessRight)/$($_.AccessControlType))"
                            })
                        } catch {}

                        # NTFS permissions on share root
                        $aNTFSPerms = @()
                        if ($bIncludeNTFS -and $oShare.Path -and (Test-Path $oShare.Path)) {
                            try {
                                $oACL = Get-Acl -Path $oShare.Path -ErrorAction Stop
                                $aNTFSPerms = @($oACL.Access | Where-Object { -not $_.IsInherited } | ForEach-Object {
                                    "$($_.IdentityReference) ($($_.FileSystemRights)/$($_.AccessControlType))"
                                })
                            } catch {}
                        }

                        [PSCustomObject]@{
                            Name             = $oShare.Name
                            Path             = $oShare.Path
                            Description      = $oShare.Description
                            ShareState       = $oShare.ShareState
                            SharePermissions = ($aSharePerms -join '; ')
                            NTFSPermissions  = if ($bIncludeNTFS) { ($aNTFSPerms -join '; ') } else { $null }
                        }
                    }
                } -ArgumentList $ExcludeSystem, $IncludeNTFS.IsPresent

                foreach ($oShare in $aShares) {
                    $hObj = [ordered]@{
                        server           = $sServer
                        name             = $oShare.Name
                        path             = $oShare.Path
                        description      = $oShare.Description
                        shareState       = $oShare.ShareState
                        sharePermissions = $oShare.SharePermissions
                    }
                    if ($IncludeNTFS) {
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
