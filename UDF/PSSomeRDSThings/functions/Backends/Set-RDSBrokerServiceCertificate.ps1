function Set-RDSBrokerServiceCertificate {
    <#
    .SYNOPSIS
    Applies a certificate directly to the RD Web Access (IIS) and RD Gateway services of a server.

    .DESCRIPTION
    RDManagement\Set-RDCertificate records the certificate in the deployment, then pushes it to the
    role services through an extra WinRM connection. Run through the workflow endpoint from a remote
    caller, that extra connection fails (0x8009030e) and the services keep the old certificate.

    This function does that last step with local commands on the target server (no second hop):
      1. imports the PFX into Cert:\LocalMachine\My when the certificate is not there yet,
      2. RDWebAccess: replaces the certificate of every https binding of 'Default Web Site'
         (WebAdministration), creating a *:443 binding when none exists,
      3. RDGateway: grants NETWORK SERVICE read access to the private key, calls
         Win32_TSGatewayServerSettings.SetCertificate and restarts the TSGateway service
         (connected gateway users are disconnected).

    Internal backend: used by Set-RDSBrokerCertificate when the verification shows that a service
    still uses another certificate.

    .PARAMETER Session
    A PSSession opened to the server hosting the services (standard endpoint).

    .PARAMETER PfxPath
    Absolute path to the PFX file on the REMOTE machine.

    .PARAMETER Password
    SecureString password protecting the PFX.

    .PARAMETER Thumbprint
    Thumbprint of the certificate inside the PFX.

    .PARAMETER Roles
    RDWebAccess and/or RDGateway.

    .OUTPUTS
    [pscustomobject[]] One per role: Role, Success, Error.

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
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory)]
        [string]$PfxPath,
        [Parameter(Mandatory)]
        [securestring]$Password,
        [Parameter(Mandatory)]
        [string]$Thumbprint,
        [Parameter(Mandatory)]
        [ValidateSet('RDGateway','RDWebAccess')]
        [string[]]$Roles
    )
    Invoke-Command -Session $Session -ScriptBlock {
        param($PfxPath, $Password, $Thumbprint, $Roles)

        # 1. Certificate in the machine store
        $oCert = Get-Item -Path "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction SilentlyContinue
        if (-not $oCert) {
            try {
                Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation 'Cert:\LocalMachine\My' -Password $Password -ErrorAction Stop | Out-Null
                $oCert = Get-Item -Path "Cert:\LocalMachine\My\$Thumbprint" -ErrorAction Stop
            } catch {
                foreach ($r in $Roles) {
                    [pscustomobject]@{ Role = $r; Success = $false; Error = "Cannot import the PFX in LocalMachine\My: $($_.Exception.Message)" }
                }
                return
            }
        }

        foreach ($r in $Roles) {
            try {
                if ($r -eq 'RDWebAccess') {
                    Import-Module WebAdministration -ErrorAction Stop
                    $aBindings = @(Get-WebBinding -Name 'Default Web Site' -Protocol https -ErrorAction Stop)
                    if ($aBindings.Count -eq 0) {
                        New-WebBinding -Name 'Default Web Site' -Protocol https -Port 443 -IPAddress '*' -ErrorAction Stop | Out-Null
                        $aBindings = @(Get-WebBinding -Name 'Default Web Site' -Protocol https -ErrorAction Stop)
                    }
                    foreach ($oBinding in $aBindings) {
                        # AddSslCertificate fails when a certificate is already bound: remove it first
                        # (their output would mix with the results: discard it)
                        if ($oBinding.certificateHash) { $oBinding.RemoveSslCertificate() | Out-Null }
                        $oBinding.AddSslCertificate($Thumbprint, 'My') | Out-Null
                    }
                } elseif ($r -eq 'RDGateway') {
                    # TSGateway runs as NETWORK SERVICE and must read the private key
                    try {
                        $oRsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($oCert)
                        $sKeyName = $null
                        if ($oRsa) {
                            if ($oRsa.Key -and $oRsa.Key.UniqueName) {
                                $sKeyName = $oRsa.Key.UniqueName
                            } elseif ($oRsa.CspKeyContainerInfo -and $oRsa.CspKeyContainerInfo.UniqueKeyContainerName) {
                                $sKeyName = $oRsa.CspKeyContainerInfo.UniqueKeyContainerName
                            }
                        }
                        if ($sKeyName) {
                            foreach ($p in @("$env:ProgramData\Microsoft\Crypto\Keys\$sKeyName",
                                             "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$sKeyName",
                                             "$env:ProgramData\Microsoft\Crypto\SystemKeys\$sKeyName")) {
                                if (Test-Path -LiteralPath $p -PathType Leaf) {
                                    $oAcl = Get-Acl -LiteralPath $p
                                    $oAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule('NT AUTHORITY\NETWORK SERVICE', 'Read', 'Allow')))
                                    Set-Acl -LiteralPath $p -AclObject $oAcl | Out-Null
                                    break
                                }
                            }
                        }
                    } catch {
                        Write-Warning "Could not grant NETWORK SERVICE access to the private key: $_"
                    }
                    $bHash = [byte[]]@(for ($i = 0; $i -lt $Thumbprint.Length; $i += 2) { [Convert]::ToByte($Thumbprint.Substring($i, 2), 16) })
                    $oGW = Get-CimInstance -Namespace 'root\cimv2\TerminalServices' -ClassName 'Win32_TSGatewayServerSettings' -ErrorAction Stop |
                        Select-Object -First 1
                    $oRet = Invoke-CimMethod -InputObject $oGW -MethodName SetCertificate -Arguments @{ CertHash = $bHash } -ErrorAction Stop
                    if ($oRet.ReturnValue -ne 0) { throw "Win32_TSGatewayServerSettings.SetCertificate returned $($oRet.ReturnValue)" }
                    Restart-Service -Name TSGateway -Force -ErrorAction Stop | Out-Null
                }
                [pscustomobject]@{ Role = $r; Success = $true; Error = $null }
            } catch {
                [pscustomobject]@{ Role = $r; Success = $false; Error = $_.Exception.Message }
            }
        }
    } -ArgumentList $PfxPath, $Password, $Thumbprint.ToUpper(), $Roles
}
