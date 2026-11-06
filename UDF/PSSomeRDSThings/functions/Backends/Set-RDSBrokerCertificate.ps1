function Set-RDSBrokerCertificate {
    <#
    .SYNOPSIS
    Assigns a PFX to one or more RDS roles via the Connection Broker.

    .DESCRIPTION
    Calls RDManagement\Set-RDCertificate -Role <X> -Path -Password -RDManagementServer for each
    requested role, through the broker's Server Manager workflow endpoint (see
    New-RDSManagementSession). This is what Set-RDCertificate does internally, without the double
    hop that breaks it when it runs inside a PSSession.

    The PFX must already be present on the broker at -PfxPath (the public dispatcher copies it into
    a temporary location before calling this backend).

    When -ExpectedThumbprint is given, the certificate of each role is read back afterwards and a
    role whose thumbprint does not match is reported as failed (the workflow activity does not
    always raise an error).

    Internal backend: do not call directly, use Set-RDSCertificate.

    .PARAMETER Session
    A PSSession opened to the Connection Broker (standard endpoint). Used to resolve its FQDN.

    .PARAMETER PfxPath
    Absolute path to the PFX file on the REMOTE machine.

    .PARAMETER Password
    SecureString password protecting the PFX.

    .PARAMETER Roles
    One or more of RDGateway, RDPublishing, RDRedirector, RDWebAccess.

    .PARAMETER Credential
    Administrator credential of the broker, used to open the workflow endpoint. Current user when
    omitted.

    .PARAMETER ExpectedThumbprint
    Thumbprint of the certificate inside the PFX, used to verify the result.

    .OUTPUTS
    [pscustomobject[]] One per role: Role, Success, Error, Warning.
    When the certificate is verified in place but the activity reported an error (typically a
    follow-up WinRM step failing with 0x8009030e), the role is Success with a Warning.

    .NOTES
        Author  : Loïc Ade
        Version : 2.0.0

        CHANGELOG:

        Version 2.0.0 - 2026-10-25 - Loïc Ade
            - Uses RDManagement\Set-RDCertificate on the ServerManagerWorkflows endpoint instead of
              Set-RDCertificate in the session (fixes the double hop failure and the RemoteDesktop
              localization issue)
            - Added -Credential and -ExpectedThumbprint (read-back verification)
            - Verification also checks the certificate really used by RD Gateway and IIS on the
              broker (Get-RDSBrokerEffectiveCertificate); an error from a follow-up step is
              downgraded to a warning when the certificate is verified in place
            - Error messages are shortened to their first sentence
            - When IIS (RD Web Access) or RD Gateway still use another certificate after the update,
              the certificate is applied to them locally (Set-RDSBrokerServiceCertificate)

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
        [string[]]$Roles,
        [pscredential]$Credential,
        [string]$ExpectedThumbprint
    )
    $sBroker = Invoke-Command -Session $Session -ScriptBlock { [System.Net.Dns]::GetHostByName($env:COMPUTERNAME).HostName }
    $oMgmt = New-RDSManagementSession -ComputerName $sBroker -Credential $Credential
    try {
        $aResults = foreach ($r in $Roles) {
            $hParams = @{
                Role               = $r
                Path               = $PfxPath
                Password           = $Password
                RDManagementServer = $sBroker
            }
            try {
                Invoke-Command -Session $oMgmt -ScriptBlock {
                    param($p) RDManagement\Set-RDCertificate @p
                } -ArgumentList $hParams -ErrorAction Stop | Out-Null
                [pscustomobject]@{ Role = $r; Success = $true; Error = $null; Warning = $null }
            } catch {
                # Keep the first sentence only (WinRM errors append a long troubleshooting text)
                $sMsg = (($_.Exception.Message -split "`r?`n")[0] -split '\s+Possible causes')[0].Trim()
                [pscustomobject]@{ Role = $r; Success = $false; Error = $sMsg; Warning = $null }
            }
        }

        if ($ExpectedThumbprint) {
            # 1. What the deployment (RDMS) now records for each role
            $aNow = @(Invoke-Command -Session $oMgmt -ScriptBlock { RDManagement\Get-RemoteDesktopCertificate } -ErrorAction SilentlyContinue)
            # 2. What the services hosted on the broker actually use (local checks, no hop)
            $hEffective = Get-RDSBrokerEffectiveCertificate -Session $Session

            # 3. Services still on another certificate (the activity's push step failed): apply it
            #    locally on the server, then check again
            $aToRepair = @($aResults | Where-Object {
                ($_.Role -in 'RDWebAccess', 'RDGateway') -and $hEffective[$_.Role] -and ($hEffective[$_.Role] -ne $ExpectedThumbprint)
            } | ForEach-Object { $_.Role })
            $hRepair = @{}
            if ($aToRepair.Count -gt 0) {
                Write-Verbose "Applying the certificate directly to: $($aToRepair -join ', ')"
                $aRepair = @(Set-RDSBrokerServiceCertificate -Session $Session -PfxPath $PfxPath -Password $Password `
                        -Thumbprint $ExpectedThumbprint -Roles $aToRepair)
                # Keep only the result objects (anything else written by remote commands is ignored)
                foreach ($oRep in ($aRepair | Where-Object { $_ -and $_.PSObject.Properties['Role'] -and $_.Role })) {
                    $hRepair[[string]$oRep.Role] = $oRep
                }
                $hEffective = Get-RDSBrokerEffectiveCertificate -Session $Session
            }

            foreach ($oRes in $aResults) {
                $oRep = $hRepair[$oRes.Role]
                if ($oRep -and -not $oRep.Success) {
                    $oRes.Error = "Could not apply the certificate to the service: $($oRep.Error)" +
                        $(if ($oRes.Error) { " (activity: $($oRes.Error))" } else { "" })
                }
                $oNow = $aNow | Where-Object { [string]$_.Role -eq $oRes.Role } | Select-Object -First 1
                $bRecorded = $oNow -and ([string]$oNow.Thumbprint -eq $ExpectedThumbprint)
                $sEffective = $hEffective[$oRes.Role]
                if (-not $bRecorded) {
                    $oRes.Success = $false
                    if (-not $oRes.Error) { $oRes.Error = "The role still uses certificate $($oNow.Thumbprint) after the update" }
                } elseif ($sEffective -and ($sEffective -ne $ExpectedThumbprint)) {
                    $oRes.Success = $false
                    $oRes.Error = "Recorded in the deployment, but the service still uses certificate $sEffective" +
                        $(if ($oRes.Error) { " (step failed: $($oRes.Error))" } else { "" })
                } elseif ($oRep -and $oRep.Success) {
                    # The push step of the activity did not reach the service: done locally instead
                    $oRes.Success = $true
                    $oRes.Warning = "Certificate applied directly to the service on the server (the deployment could not push it)"
                    $oRes.Error = $null
                } elseif (-not $oRes.Success) {
                    # The certificate is in place: the error came from a follow-up remote step
                    $oRes.Success = $true
                    $oRes.Warning = "Applied and verified, but a follow-up step reported: $($oRes.Error)"
                    $oRes.Error = $null
                }
            }
        }
        return $aResults
    } finally {
        Remove-PSSession -Session $oMgmt -ErrorAction SilentlyContinue
    }
}
