function Get-RDSCertificate {
    <#
    .SYNOPSIS
    Reads the current certificate(s) used by a Remote Desktop Services server.

    .DESCRIPTION
    Detects the deployment mode (Broker vs Standalone) and dispatches to the matching backend:
    - Broker mode returns one entry per RDS role (RDGateway, RDPublishing, RDRedirector, RDWebAccess)
      using Get-RDCertificate.
    - Standalone mode returns a single entry for the RDP-tcp listener cert read from
      Win32_TSGeneralSetting.

    SAN parsing happens locally (caller side) via Get-CertificateSAN, which is locale-independent.
    Pass -DeploymentMode to skip the auto-detection.

    .PARAMETER Session
    A PSSession opened to the target server.

    .PARAMETER DeploymentMode
    Optional override. 'Broker' or 'Standalone'. Auto-detected when omitted.

    .OUTPUTS
    [pscustomobject] with DeploymentMode, ComputerName, Certificates[].
    Each Certificates[] entry has Role, Thumbprint, Level (Broker only), Subject, SAN, NotBefore,
    NotAfter, IssuedTo, IssuedBy.

    .EXAMPLE
    $info = Get-RDSCertificate -Session $session
    $info.Certificates | Format-Table Role, NotAfter, Thumbprint

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-05-18 - Loïc Ade
            - Initial release
            - Dispatches between Broker (Get-RDCertificate) and Standalone (Win32_TSGeneralSetting)
              backends based on Get-RDSDeploymentMode
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [ValidateSet('Broker','Standalone')]
        [string]$DeploymentMode
    )
    if (-not $DeploymentMode) {
        $DeploymentMode = Get-RDSDeploymentMode -Session $Session
    }
    $aRaw = switch ($DeploymentMode) {
        'Broker'     { Get-RDSBrokerCertificate -Session $Session }
        'Standalone' { Get-RDSStandaloneCertificate -Session $Session }
    }
    $aCerts = foreach ($oItem in $aRaw) {
        $hSAN = @{ DNS = @(); IP = @() }
        if ($oItem.RawData) {
            try {
                $oCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,[byte[]]$oItem.RawData)
                $hSANByType = Get-CertificateSAN -Certificate $oCert
                if ($hSANByType.Contains('DNS_NAME'))   { $hSAN.DNS = @($hSANByType.DNS_NAME) }
                if ($hSANByType.Contains('IP_ADDRESS')) { $hSAN.IP  = @($hSANByType.IP_ADDRESS) }
            } catch {
                Write-Warning "Failed to parse SAN for role $($oItem.Role): $_"
            }
        }
        [pscustomobject]@{
            Role       = $oItem.Role
            Thumbprint = $oItem.Thumbprint
            Level      = $oItem.Level
            Subject    = $oItem.Subject
            SAN        = $hSAN
            NotBefore  = $oItem.NotBefore
            NotAfter   = $oItem.NotAfter
            IssuedTo   = $oItem.IssuedTo
            IssuedBy   = $oItem.IssuedBy
        }
    }
    return [pscustomobject]@{
        DeploymentMode = $DeploymentMode
        ComputerName   = $Session.ComputerName
        Certificates   = @($aCerts)
    }
}
