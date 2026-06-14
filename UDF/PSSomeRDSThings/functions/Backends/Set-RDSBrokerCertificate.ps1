function Set-RDSBrokerCertificate {
    <#
    .SYNOPSIS
    Assigns a PFX to one or more RDS roles via the Connection Broker.

    .DESCRIPTION
    Calls Set-RDCertificate -Role <X> -ImportPath -Password for each requested role on the broker.
    The PFX must already be present on the remote machine at -PfxPath (the public dispatcher copies
    it into a temporary location before calling this backend).

    Internal backend: do not call directly, use Set-RDSCertificate.

    .PARAMETER Session
    A PSSession opened to the Connection Broker.

    .PARAMETER PfxPath
    Absolute path to the PFX file on the REMOTE machine.

    .PARAMETER Password
    SecureString password protecting the PFX.

    .PARAMETER Roles
    One or more of RDGateway, RDPublishing, RDRedirector, RDWebAccess.

    .OUTPUTS
    [pscustomobject[]] One per role: Role, Success, Error.

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-05-18 - Loïc Ade
            - Initial release
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory)]
        [string]$PfxPath,
        [Parameter(Mandatory)]
        [securestring]$Password,
        [Parameter(Mandatory)]
        [ValidateSet('RDGateway','RDPublishing','RDRedirector','RDWebAccess')]
        [string[]]$Roles
    )
    Invoke-Command -Session $Session -ScriptBlock {
        param($PfxPath, $Password, $Roles)
        Import-Module RemoteDesktop -ErrorAction Stop
        $sBroker = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
        foreach ($r in $Roles) {
            try {
                Set-RDCertificate -Role $r -ImportPath $PfxPath -Password $Password -ConnectionBroker $sBroker -Force -ErrorAction Stop
                [pscustomobject]@{ Role = $r; Success = $true; Error = $null }
            } catch {
                [pscustomobject]@{ Role = $r; Success = $false; Error = $_.Exception.Message }
            }
        }
    } -ArgumentList $PfxPath, $Password, $Roles
}
