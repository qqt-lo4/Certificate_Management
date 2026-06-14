function Set-RDSCertificate {
    <#
    .SYNOPSIS
    Deploys a PFX certificate to a Remote Desktop Services server.

    .DESCRIPTION
    Auto-detects deployment mode (Broker vs Standalone) and dispatches to the matching backend:
    - Broker: applies the cert to the requested RDS roles via Set-RDCertificate. Defaults to all 4
      roles (RDGateway, RDPublishing, RDRedirector, RDWebAccess) when -Roles is omitted.
    - Standalone: imports the cert into the LocalMachine\My store, grants NETWORK SERVICE access to
      the private key, and binds it on the RDP-tcp listener (Win32_TSGeneralSetting). -Roles is
      ignored in Standalone mode.

    The PFX is copied to a temporary location on the remote machine, then removed in a finally
    block whether the assignment succeeded or not.

    .PARAMETER Session
    A PSSession opened to the target server.

    .PARAMETER PfxPath
    Path to the PFX file on the LOCAL machine (calling side).

    .PARAMETER Password
    SecureString password protecting the PFX.

    .PARAMETER DeploymentMode
    Optional override. 'Broker' or 'Standalone'. Auto-detected when omitted.

    .PARAMETER Roles
    Broker mode only. Subset of RDGateway, RDPublishing, RDRedirector, RDWebAccess. Defaults to all 4.

    .OUTPUTS
    [pscustomobject] with DeploymentMode, Success, RoleResults[].

    .EXAMPLE
    Set-RDSCertificate -Session $session -PfxPath 'C:\certs\new.pfx' -Password $secret

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-05-18 - Loïc Ade
            - Initial release
            - Dispatches between Broker (Set-RDCertificate per role) and Standalone
              (Import-PfxCertificate + NETWORK SERVICE ACL + Win32_TSGeneralSetting) backends
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory)]
        [string]$PfxPath,
        [Parameter(Mandatory)]
        [securestring]$Password,
        [ValidateSet('Broker','Standalone')]
        [string]$DeploymentMode,
        [ValidateSet('RDGateway','RDPublishing','RDRedirector','RDWebAccess')]
        [string[]]$Roles
    )

    if (-not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) {
        throw "PFX file not found: $PfxPath"
    }

    if (-not $DeploymentMode) {
        $DeploymentMode = Get-RDSDeploymentMode -Session $Session
    }

    $sRemoteTemp = Invoke-Command -Session $Session -ScriptBlock {
        Join-Path $env:TEMP ("rdcert_" + [Guid]::NewGuid().ToString('N') + ".pfx")
    }
    Copy-Item -LiteralPath $PfxPath -Destination $sRemoteTemp -ToSession $Session -Force

    try {
        $aRoleResults = switch ($DeploymentMode) {
            'Broker' {
                if (-not $Roles -or $Roles.Count -eq 0) {
                    $Roles = @('RDGateway','RDPublishing','RDRedirector','RDWebAccess')
                }
                Set-RDSBrokerCertificate -Session $Session -PfxPath $sRemoteTemp -Password $Password -Roles $Roles
            }
            'Standalone' {
                if ($Roles -and $Roles.Count -gt 0) {
                    Write-Warning "Roles parameter is ignored in Standalone deployment mode (only the RDP listener is configured)."
                }
                Set-RDSStandaloneCertificate -Session $Session -PfxPath $sRemoteTemp -Password $Password
            }
        }
    } finally {
        Invoke-Command -Session $Session -ScriptBlock {
            param($p)
            Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
        } -ArgumentList $sRemoteTemp
    }

    $bSuccess = ($aRoleResults | Where-Object { -not $_.Success }).Count -eq 0
    return [pscustomobject]@{
        DeploymentMode = $DeploymentMode
        Success        = $bSuccess
        RoleResults    = @($aRoleResults)
    }
}
