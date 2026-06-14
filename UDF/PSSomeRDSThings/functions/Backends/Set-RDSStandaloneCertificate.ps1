function Set-RDSStandaloneCertificate {
    <#
    .SYNOPSIS
    Imports a PFX and assigns it to the RDP-tcp listener on a standalone Session Host.

    .DESCRIPTION
    Performs three steps on the remote session:
      1. Import-PfxCertificate into Cert:\LocalMachine\My (Exportable so the key can be re-exported
         for backups / re-deployment).
      2. Grants NETWORK SERVICE Read access to the private key file. Without this, the RDP listener
         service cannot use the key. Both CSP and CNG key storage locations are probed.
      3. Sets Win32_TSGeneralSetting.SSLCertificateSHA1Hash for TerminalName='RDP-tcp' to the new
         thumbprint.

    Internal backend: do not call directly, use Set-RDSCertificate.

    .PARAMETER Session
    A PSSession opened to the standalone RDS server.

    .PARAMETER PfxPath
    Absolute path to the PFX file on the REMOTE machine.

    .PARAMETER Password
    SecureString password protecting the PFX.

    .OUTPUTS
    [pscustomobject[]] Single entry: Role = 'RDP-Listener', Success, Error, NewThumbprint.

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
        [securestring]$Password
    )
    Invoke-Command -Session $Session -ScriptBlock {
        param($PfxPath, $Password)
        try {
            $oImport = Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation 'Cert:\LocalMachine\My' -Password $Password -Exportable -ErrorAction Stop
            $sThumb = $oImport.Thumbprint
            $oCert = Get-Item -Path "Cert:\LocalMachine\My\$sThumb"

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
                    $aKeyPaths = @(
                        "$env:ProgramData\Microsoft\Crypto\Keys\$sKeyName",
                        "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$sKeyName",
                        "$env:ProgramData\Microsoft\Crypto\SystemKeys\$sKeyName"
                    )
                    foreach ($p in $aKeyPaths) {
                        if (Test-Path -LiteralPath $p -PathType Leaf) {
                            $oAcl = Get-Acl -LiteralPath $p
                            $oRule = New-Object System.Security.AccessControl.FileSystemAccessRule('NT AUTHORITY\NETWORK SERVICE','Read','Allow')
                            $oAcl.AddAccessRule($oRule)
                            Set-Acl -LiteralPath $p -AclObject $oAcl
                            break
                        }
                    }
                }
            } catch {
                Write-Warning "Could not grant NETWORK SERVICE access to private key: $_"
            }

            $oTsg = Get-CimInstance -Namespace 'root\cimv2\TerminalServices' -ClassName 'Win32_TSGeneralSetting' -Filter "TerminalName='RDP-tcp'" -ErrorAction Stop
            $oTsg | Set-CimInstance -Property @{ SSLCertificateSHA1Hash = $sThumb } -ErrorAction Stop

            return ,[pscustomobject]@{ Role = 'RDP-Listener'; Success = $true; Error = $null; NewThumbprint = $sThumb }
        } catch {
            return ,[pscustomobject]@{ Role = 'RDP-Listener'; Success = $false; Error = $_.Exception.Message; NewThumbprint = $null }
        }
    } -ArgumentList $PfxPath, $Password
}
