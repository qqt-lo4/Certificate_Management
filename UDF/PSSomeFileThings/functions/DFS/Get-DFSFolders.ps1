function Get-DFSFolders {
    <#
    .SYNOPSIS
        Lists DFS folders under a namespace with their targets.

    .DESCRIPTION
        Enumerates DFS folders (links) and resolves each folder's target path(s).
        Executes Get-DfsnFolder/Get-DfsnFolderTarget via Invoke-Command on the DFS
        server (which has RSAT DFS tools installed).

    .PARAMETER Path
        One or more DFS paths to enumerate. Supports wildcards in the last segment
        (e.g. "\\domain\ns\folder\dump*", "\\domain\ns\folder\*").

    .PARAMETER ComputerName
        The DFS server to execute on. Required.

    .PARAMETER Credential
        Credentials for remote execution. Optional.

    .OUTPUTS
        [PSCustomObject[]] Objects with dfsPath, folderName, targetPath, targetServer, state.

    .EXAMPLE
        Get-DFSFolders -Path "\\contoso.com\shares\*" -ComputerName "DFS01"

    .EXAMPLE
        Get-DFSFolders -Path "\\contoso.com\shares\dump*" -ComputerName "DFS01" -Credential $cred

    .NOTES
        Author  : Loic Ade
        Version : 2.0.0

        2.0.0 (2026-04-01) - Execute via Invoke-Command on DFS server
        1.0.0 (2026-04-01) - Initial version (local RSAT)
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string[]]$Path,

        [Parameter(Mandatory)]
        [string]$ComputerName,

        [PSCredential]$Credential
    )

    Process {
        $hRemoteParams = @{ ComputerName = $ComputerName }
        if ($Credential) { $hRemoteParams['Credential'] = $Credential }

        # Forward the caller's $WarningPreference into the remote
        # scriptblock so -WarningAction SilentlyContinue at the call
        # site actually mutes the "Cannot enumerate" warning written
        # below. Invoke-Command does not propagate preference
        # variables across the remoting boundary on PS 5.1 - we have
        # to pass it explicitly via -ArgumentList and re-apply inside.
        $sWP = $WarningPreference
        try {
            $aResults = @(Invoke-Command @hRemoteParams -ScriptBlock {
                param($aPatterns, $sWPRemote)
                $WarningPreference = $sWPRemote
                $aAll = @()
                foreach ($sPattern in $aPatterns) {
                    try {
                        $aFolders = @(Get-DfsnFolder -Path $sPattern -ErrorAction Stop)
                        foreach ($oFolder in $aFolders) {
                            $aTargets = @()
                            try {
                                $aTargets = @(Get-DfsnFolderTarget -Path $oFolder.Path -ErrorAction Stop)
                            } catch {}

                            if ($aTargets.Count -eq 0) {
                                $aAll += [PSCustomObject]@{
                                    DFSPath      = $oFolder.Path
                                    FolderName   = ($oFolder.Path -split '\\')[-1]
                                    TargetPath   = $null
                                    TargetServer = $null
                                    State        = $oFolder.State
                                }
                            } else {
                                foreach ($oTarget in $aTargets) {
                                    $sServer = ($oTarget.TargetPath -replace '^\\\\', '') -split '\\' | Select-Object -First 1
                                    $aAll += [PSCustomObject]@{
                                        DFSPath      = $oFolder.Path
                                        FolderName   = ($oFolder.Path -split '\\')[-1]
                                        TargetPath   = $oTarget.TargetPath
                                        TargetServer = $sServer
                                        State        = $oTarget.State
                                    }
                                }
                            }
                        }
                    } catch {
                        Write-Warning "Get-DFSFolders: Cannot enumerate '$sPattern' - $_"
                    }
                }
                return $aAll
            } -ArgumentList (,$Path), $sWP)
        } catch {
            Write-Warning "Get-DFSFolders: Cannot connect to '$ComputerName' - $_"
            return @()
        }

        # Normalize output (Invoke-Command adds PSComputerName etc.)
        return @($aResults | ForEach-Object {
            [PSCustomObject][ordered]@{
                dfsPath      = $_.DFSPath
                folderName   = $_.FolderName
                targetPath   = $_.TargetPath
                targetServer = $_.TargetServer
                state        = $_.State
            }
        })
    }
}
