function Get-RDSBrokerCertificate {
    <#
    .SYNOPSIS
    Reads the current RDS certificate for each role on a Connection Broker.

    .DESCRIPTION
    Calls RDManagement\Get-RemoteDesktopCertificate through the broker's Server Manager workflow
    endpoint (see New-RDSManagementSession), which avoids the double hop that breaks
    Get-RDCertificate when it runs inside a PSSession.

    For RDGateway and RDWebAccess, the role is flagged Available = $false when no server of the
    deployment holds it (same rule as Get-RDCertificate).

    RawData is returned so the caller can parse SAN locally with Get-CertificateSAN
    (locale-independent).

    Internal backend: do not call directly, use Get-RDSCertificate.

    .PARAMETER Session
    A PSSession opened to the Connection Broker (standard endpoint). Used to resolve its FQDN.

    .PARAMETER Credential
    Administrator credential of the broker, used to open the workflow endpoint. Current user when
    omitted.

    .OUTPUTS
    [pscustomobject[]] One per role (RDGateway, RDPublishing, RDRedirector, RDWebAccess).

    .NOTES
        Author  : Loïc Ade
        Version : 2.0.0

        CHANGELOG:

        Version 2.0.0 - 2026-10-25 - Loïc Ade
            - Uses RDManagement\Get-RemoteDesktopCertificate on the ServerManagerWorkflows endpoint
              instead of Get-RDCertificate in the session (fixes the double hop failure and the
              RemoteDesktop localization issue)
            - Added -Credential and the Available property

        Version 1.0.0 - 2026-05-18 - Loïc Ade
            - Initial release
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [pscredential]$Credential
    )
    $sBroker = Invoke-Command -Session $Session -ScriptBlock { [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName }
    $oMgmt = New-RDSManagementSession -ComputerName $sBroker -Credential $Credential
    try {
        $aRDCerts = @(Invoke-Command -Session $oMgmt -ScriptBlock { RDManagement\Get-RemoteDesktopCertificate } -ErrorAction Stop)
        $aGateway = @(Invoke-Command -Session $oMgmt -ScriptBlock {
            param($b) RDManagement\Get-RDMSJoinedNode -ManagementServer $b -Roles RDS-GATEWAY
        } -ArgumentList $sBroker -ErrorAction SilentlyContinue)
        $aWebAccess = @(Invoke-Command -Session $oMgmt -ScriptBlock {
            param($b) RDManagement\Get-RDMSJoinedNode -ManagementServer $b -Roles RDS-WEB-ACCESS
        } -ArgumentList $sBroker -ErrorAction SilentlyContinue)
    } finally {
        Remove-PSSession -Session $oMgmt -ErrorAction SilentlyContinue
    }

    foreach ($oRDCert in $aRDCerts) {
        $sRole = [string]$oRDCert.Role
        $bAvailable = switch ($sRole) {
            'RDGateway'   { $aGateway.Count -gt 0 }
            'RDWebAccess' { $aWebAccess.Count -gt 0 }
            default       { $true }
        }
        $sLevel = [string]$oRDCert.Level
        $bConfigured = $bAvailable -and ($sLevel -ne 'NotConfigured') -and $oRDCert.Thumbprint
        $hItem = [ordered]@{
            Role       = $sRole
            Level      = if ($bAvailable) { $sLevel } else { 'RoleNotInstalled' }
            Available  = $bAvailable
            Thumbprint = $null
            ExpiresOn  = $null
            IssuedTo   = $null
            IssuedBy   = $null
            Subject    = $null
            NotBefore  = $null
            NotAfter   = $null
            RawData    = $null
        }
        if ($bConfigured) {
            $hItem.Thumbprint = [string]$oRDCert.Thumbprint
            $hItem.IssuedTo   = $oRDCert.IssuedTo
            $hItem.IssuedBy   = $oRDCert.IssuedBy
            $hItem.Subject    = $oRDCert.Subject
            if ($oRDCert.NotAfter -and ([datetime]$oRDCert.NotAfter) -ne [datetime]::MinValue) {
                $hItem.NotAfter  = [datetime]$oRDCert.NotAfter
                $hItem.ExpiresOn = $hItem.NotAfter
            }
            if ($oRDCert.RawData) {
                $hItem.RawData = [byte[]]@($oRDCert.RawData)
                try {
                    $oX509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$hItem.RawData)
                    $hItem.NotBefore = $oX509.NotBefore
                    if (-not $hItem.NotAfter) { $hItem.NotAfter = $oX509.NotAfter; $hItem.ExpiresOn = $oX509.NotAfter }
                } catch {
                    Write-Verbose "Could not parse certificate RawData for role $sRole : $_"
                }
            }
        }
        [pscustomobject]$hItem
    }
}
