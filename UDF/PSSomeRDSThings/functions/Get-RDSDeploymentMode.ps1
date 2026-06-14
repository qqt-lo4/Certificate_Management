function Get-RDSDeploymentMode {
    <#
    .SYNOPSIS
    Detects whether a target server is in an RDS Broker deployment or a standalone Session Host configuration.

    .DESCRIPTION
    Inspects the target machine to determine which certificate mechanism applies:
    - 'Broker': the RDS Connection Broker role is installed, certificate management goes through
      the RemoteDesktop module (Get-RDCertificate / Set-RDCertificate) for the 4 RDS roles
      (RDGateway, RDRedirector, RDPublishing, RDWebAccess).
    - 'Standalone': only the RDP listener cert is managed, via Win32_TSGeneralSetting.

    Detection order:
      1. RDS-Connection-Broker Windows feature installed -> Broker
      2. RemoteDesktop module available and Get-RDServer succeeds -> Broker
      3. Otherwise -> Standalone

    .PARAMETER Session
    A PSSession opened to the target server.

    .OUTPUTS
    [string] 'Broker' or 'Standalone'

    .EXAMPLE
    Get-RDSDeploymentMode -Session $session
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )
    return Invoke-Command -Session $Session -ScriptBlock {
        $oFeature = Get-WindowsFeature -Name 'RDS-Connection-Broker' -ErrorAction SilentlyContinue
        if ($oFeature -and $oFeature.Installed) {
            return 'Broker'
        }
        if (Get-Module -ListAvailable -Name RemoteDesktop -ErrorAction SilentlyContinue) {
            try {
                Import-Module RemoteDesktop -ErrorAction Stop
                $null = Get-RDServer -ErrorAction Stop
                return 'Broker'
            } catch {
                # fall through to Standalone
            }
        }
        return 'Standalone'
    }
}
