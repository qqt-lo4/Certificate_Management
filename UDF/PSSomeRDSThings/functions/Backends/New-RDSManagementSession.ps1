function New-RDSManagementSession {
    <#
    .SYNOPSIS
    Opens a PSSession to the Server Manager workflow endpoint of an RDS Connection Broker.

    .DESCRIPTION
    The RemoteDesktop module cmdlets (Get-RDCertificate, Set-RDCertificate...) are wrappers: they
    open a session to the 'Microsoft.Windows.ServerManagerWorkflows' endpoint of the broker and call
    the RDManagement activities there (Get-RemoteDesktopCertificate, Set-RDCertificate...).
    Run from inside a PSSession, that inner connection is a second hop and fails ("The RD Connection
    Broker server is not available").

    Opening that endpoint directly from the caller is a single hop: no CredSSP, no delegation and no
    configuration is needed. It is the endpoint Server Manager itself uses remotely.

    The endpoint is restricted: only call RDManagement commands in it (no Select-Object, etc.) and
    process the results on the caller side.

    Internal backend: used by the Broker backends of PSSomeRDSThings.

    .PARAMETER ComputerName
    FQDN of the Connection Broker.

    .PARAMETER Credential
    Administrator credential of the broker. Current user when omitted.

    .OUTPUTS
    [System.Management.Automation.Runspaces.PSSession]

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-10-25 - Loïc Ade
            - Initial release
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        [pscredential]$Credential
    )
    $hParams = @{
        ComputerName      = $ComputerName
        ConfigurationName = 'Microsoft.Windows.ServerManagerWorkflows'
        ErrorAction       = 'Stop'
    }
    if ($Credential) { $hParams.Credential = $Credential }
    return New-PSSession @hParams
}
