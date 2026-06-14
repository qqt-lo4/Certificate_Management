function Get-RDSStandaloneCertificate {
    <#
    .SYNOPSIS
    Reads the RDP listener certificate on a standalone Session Host (no Connection Broker).

    .DESCRIPTION
    Queries Win32_TSGeneralSetting (root\cimv2\TerminalServices) on the target session for the
    RDP-tcp terminal and resolves the SSLCertificateSHA1Hash thumbprint against the LocalMachine
    personal store. Returns a single-entry array (Role = 'RDP-Listener') with the same shape as
    Get-RDSBrokerCertificate so the public dispatcher can treat both modes uniformly.

    Internal backend: do not call directly, use Get-RDSCertificate.

    .PARAMETER Session
    A PSSession opened to the standalone RDS server.

    .OUTPUTS
    [pscustomobject[]] Single entry with the RDP-tcp listener cert info (or nulls if unconfigured).

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
        $oTsg = Get-CimInstance -Namespace 'root\cimv2\TerminalServices' -ClassName 'Win32_TSGeneralSetting' -Filter "TerminalName='RDP-tcp'" -ErrorAction Stop
        $sThumb = $oTsg.SSLCertificateSHA1Hash
        $hItem = [ordered]@{
            Role       = 'RDP-Listener'
            Level      = $null
            Thumbprint = $sThumb
            ExpiresOn  = $null
            IssuedTo   = $null
            IssuedBy   = $null
            Subject    = $null
            NotBefore  = $null
            NotAfter   = $null
            RawData    = $null
        }
        if ($sThumb) {
            $oCert = Get-Item -Path "Cert:\LocalMachine\My\$sThumb" -ErrorAction SilentlyContinue
            if ($oCert) {
                $hItem.Subject   = $oCert.Subject
                $hItem.NotBefore = $oCert.NotBefore
                $hItem.NotAfter  = $oCert.NotAfter
                $hItem.IssuedTo  = $oCert.Subject
                $hItem.IssuedBy  = $oCert.Issuer
                $hItem.ExpiresOn = $oCert.NotAfter
                $hItem.RawData   = $oCert.RawData
            }
        }
        return ,@([pscustomobject]$hItem)
    }
}
