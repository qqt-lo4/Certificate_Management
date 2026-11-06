function Set-MSSqlCertificate {
    <#
    .SYNOPSIS
        Prepares a new TLS certificate for a SQL Server instance, without restarting it

    .DESCRIPTION
        Performs, on the computer of the session:
          1. Import of the PFX into Cert:\LocalMachine\My (machine key, exportable). The
             intermediate certificates of the PFX go to LocalMachine\CA; root certificates are
             never added to the trusted roots.
          2. Read access to the private key for the account of the instance service, when it is
             missing (not needed for LocalSystem). Without it the instance cannot load the
             certificate and does not start.
          3. The thumbprint written in the instance configuration (SuperSocketNetLib\Certificate),
             as SQL Server Configuration Manager does.

        The encryption settings (ForceEncryption...) are not changed. SQL Server reads its
        certificate when the service starts: the new certificate is used after the next restart
        of the instance (see Restart-MSSqlInstance). Until then the current certificate stays in
        use.

        When the private key access cannot be granted, the configuration is not changed, so that
        the next restart cannot fail because of the new certificate.

        The PFX is copied to a temporary file on the remote computer and removed afterwards.

    .PARAMETER Session
        A PSSession opened to the SQL Server computer (administrator rights).

    .PARAMETER InstanceName
        Name of the instance (MSSQLSERVER for the default instance).

    .PARAMETER PfxPath
        Path of the PFX file on the LOCAL computer (calling side).

    .PARAMETER Password
        Password of the PFX.

    .OUTPUTS
        [PSCustomObject] with:
          Success, Error,
          Thumbprint, PreviousThumbprint,
          ServiceName, ServiceAccount,
          KeyStorage (e.g. "CAPI Exchange", "CNG"), KeyAccess (Granted, AlreadyGranted,
          NotNeeded), Warnings (string[])

    .EXAMPLE
        Set-MSSqlCertificate -Session $s -InstanceName MSSQLSERVER -PfxPath C:\certs\sql01.pfx -Password $pwd

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-11-06 - Loïc Ade
            - Initial release
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory)]
        [string]$InstanceName,
        [Parameter(Mandatory)]
        [string]$PfxPath,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [securestring]$Password
    )
    if (-not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) {
        throw "PFX file not found: $PfxPath"
    }

    $sRemoteTemp = Invoke-Command -Session $Session -ScriptBlock {
        Join-Path $env:TEMP ("sqlcert_" + [Guid]::NewGuid().ToString('N') + ".pfx")
    }
    Copy-Item -LiteralPath $PfxPath -Destination $sRemoteTemp -ToSession $Session -Force
    try {
        $oResult = Invoke-Command -Session $Session -ArgumentList $sRemoteTemp, $Password, $InstanceName -ScriptBlock {
            param($PfxPath, $Password, $InstanceName)
            $hResult = [ordered]@{
                Success            = $false
                Error              = $null
                Thumbprint         = $null
                PreviousThumbprint = $null
                ServiceName        = $null
                ServiceAccount     = $null
                KeyStorage         = $null
                KeyAccess          = $null
                Warnings           = @()
            }
            try {
                # Instance configuration key
                $sKey = $null
                foreach ($sRoot in "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server") {
                    $oNames = Get-ItemProperty -Path "$sRoot\Instance Names\SQL" -ErrorAction SilentlyContinue
                    if ($oNames -and $oNames.PSObject.Properties[$InstanceName]) {
                        $sKey = "$sRoot\$($oNames.$InstanceName)\MSSQLServer\SuperSocketNetLib"
                        break
                    }
                }
                if (-not $sKey -or -not (Test-Path -Path $sKey)) { throw "Instance $InstanceName not found on $env:COMPUTERNAME" }
                $hResult.PreviousThumbprint = "$((Get-ItemProperty -Path $sKey -ErrorAction SilentlyContinue).Certificate)".Trim().ToUpper()

                $sService = if ($InstanceName -eq "MSSQLSERVER") { "MSSQLSERVER" } else { 'MSSQL$' + $InstanceName }
                $oService = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $sService + "'") -ErrorAction Stop
                $hResult.ServiceName = $sService
                $hResult.ServiceAccount = $oService.StartName

                # 1. Import: machine key, persisted, exportable (default provider of the PFX)
                $pBSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
                try {
                    $sPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($pBSTR)
                } finally {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pBSTR)
                }
                $eFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor
                          [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet -bor
                          [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
                $oPfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                $oPfx.Import($PfxPath, $sPlain, $eFlags)
                $oLeaf = @($oPfx | Where-Object { $_.HasPrivateKey })[0]
                if (-not $oLeaf) { throw "The PFX does not contain a private key" }

                $oStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("My", "LocalMachine")
                $oStore.Open("ReadWrite")
                try { $oStore.Add($oLeaf) } finally { $oStore.Close() }
                $aIntermediates = @($oPfx | Where-Object { -not $_.HasPrivateKey -and ($_.Subject -ne $_.Issuer) })
                if ($aIntermediates.Count -gt 0) {
                    $oStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("CA", "LocalMachine")
                    $oStore.Open("ReadWrite")
                    try { foreach ($oCA in $aIntermediates) { $oStore.Add($oCA) } } finally { $oStore.Close() }
                }
                $sThumbprint = $oLeaf.Thumbprint.ToUpper()
                $hResult.Thumbprint = $sThumbprint

                # 2. Private key file and its storage
                $oCert = Get-Item -Path "Cert:\LocalMachine\My\$sThumbprint"
                $sKeyName = $null
                $oKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($oCert)
                if (-not $oKey) {
                    $oKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($oCert)
                }
                if ($oKey -and $oKey.PSObject.Properties["Key"] -and $oKey.Key.UniqueName) {
                    $sKeyName = $oKey.Key.UniqueName
                    $hResult.KeyStorage = "CNG"
                    $hResult.Warnings += "The private key is stored by a CNG provider. SQL Server documents keys of type AT_KEYEXCHANGE (legacy CryptoAPI provider): check in the ERRORLOG that the certificate is loaded after the restart."
                } elseif ($oKey -and $oKey.PSObject.Properties["CspKeyContainerInfo"]) {
                    $sKeyName = $oKey.CspKeyContainerInfo.UniqueKeyContainerName
                    $hResult.KeyStorage = "CAPI " + $oKey.CspKeyContainerInfo.KeyNumber
                    if ("$($oKey.CspKeyContainerInfo.KeyNumber)" -ne "Exchange") {
                        $hResult.Warnings += "The private key is not of type AT_KEYEXCHANGE: SQL Server may not load it."
                    }
                }
                $sKeyFile = $null
                if ($sKeyName) {
                    foreach ($sDir in "Microsoft\Crypto\Keys", "Microsoft\Crypto\RSA\MachineKeys", "Microsoft\Crypto\SystemKeys") {
                        $sPath = Join-Path $env:ProgramData "$sDir\$sKeyName"
                        if (Test-Path -LiteralPath $sPath -PathType Leaf) { $sKeyFile = $sPath; break }
                    }
                }

                # Read access for the service account (LocalSystem already has it)
                $sAccount = "$($oService.StartName)"
                if ($sAccount -match '^(LocalSystem|NT AUTHORITY\\SYSTEM|\.\\LocalSystem)$') {
                    $hResult.KeyAccess = "NotNeeded"
                } else {
                    if ($sAccount.StartsWith(".\")) { $sAccount = $env:COMPUTERNAME + $sAccount.Substring(1) }
                    if (-not $sKeyFile) { throw "Private key file not found: read access cannot be granted to $sAccount" }
                    $oSid = (New-Object System.Security.Principal.NTAccount($sAccount)).Translate([System.Security.Principal.SecurityIdentifier])
                    $oAcl = Get-Acl -LiteralPath $sKeyFile
                    $bGranted = $false
                    foreach ($oRule in $oAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                        if (($oRule.IdentityReference -eq $oSid) -and ($oRule.AccessControlType -eq "Allow") -and
                            (($oRule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Read) -eq [System.Security.AccessControl.FileSystemRights]::Read)) {
                            $bGranted = $true
                        }
                    }
                    if ($bGranted) {
                        $hResult.KeyAccess = "AlreadyGranted"
                    } else {
                        $oAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($oSid, "Read", "Allow")))
                        Set-Acl -LiteralPath $sKeyFile -AclObject $oAcl
                        $hResult.KeyAccess = "Granted"
                    }
                }

                # 3. Configuration of the instance (lower case, as Configuration Manager writes it)
                Set-ItemProperty -Path $sKey -Name "Certificate" -Value $sThumbprint.ToLower()
                $hResult.Success = $true
            } catch {
                $hResult.Error = $_.Exception.Message
            }
            [PSCustomObject]$hResult
        }
    } finally {
        Invoke-Command -Session $Session -ArgumentList $sRemoteTemp -ScriptBlock {
            param($p)
            Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
        }
    }
    $oResult | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
}
