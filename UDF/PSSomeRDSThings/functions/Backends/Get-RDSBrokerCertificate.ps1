function Get-RDSBrokerCertificate {
    <#
    .SYNOPSIS
    Reads the current RDS certificate for each role on a Connection Broker.

    .DESCRIPTION
    Runs Get-RDCertificate on the target session (which must be opened to the broker) and
    enriches each returned entry with the corresponding X509 information read from the local
    machine certificate store (Subject, NotBefore, NotAfter, RawData). RawData is returned so
    the caller can parse SAN locally with Get-CertificateSAN (locale-independent).

    Internal backend: do not call directly, use Get-RDSCertificate.

    .PARAMETER Session
    A PSSession opened to the Connection Broker.

    .OUTPUTS
    [pscustomobject[]] One per role (RDGateway, RDPublishing, RDRedirector, RDWebAccess).

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
        [System.Management.Automation.Runspaces.PSSession]$Session
    )
    Invoke-Command -Session $Session -ScriptBlock {
        Import-Module RemoteDesktop -ErrorAction Stop
        $sBroker = [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName
        $aResult = @()
        foreach ($oRDCert in (Get-RDCertificate -ConnectionBroker $sBroker)) {
            $hItem = [ordered]@{
                Role       = [string]$oRDCert.Role
                Level      = [string]$oRDCert.Level
                Thumbprint = $oRDCert.Thumbprint
                ExpiresOn  = $oRDCert.ExpiresOn
                IssuedTo   = $oRDCert.IssuedTo
                IssuedBy   = $oRDCert.IssuedBy
                Subject    = $null
                NotBefore  = $null
                NotAfter   = $null
                RawData    = $null
            }
            if ($oRDCert.Thumbprint) {
                $oCert = Get-Item -Path "Cert:\LocalMachine\My\$($oRDCert.Thumbprint)" -ErrorAction SilentlyContinue
                if ($oCert) {
                    $hItem.Subject   = $oCert.Subject
                    $hItem.NotBefore = $oCert.NotBefore
                    $hItem.NotAfter  = $oCert.NotAfter
                    $hItem.RawData   = $oCert.RawData
                }
            }
            $aResult += [pscustomobject]$hItem
        }
        return $aResult
    }
}
