function Install-RemoteMachineCertificate {
    <#
    .SYNOPSIS
        Installs a PFX certificate in a remote computer's LocalMachine\My store.

    .DESCRIPTION
        Imports the private key as non-exportable, adds intermediate certificates to
        LocalMachine\CA, and grants Read access to the private key for one or more accounts
        or groups. Root certificates are not added to the trusted root store.

    .PARAMETER Session
        An administrator PSSession to the target computer.

    .PARAMETER PfxPath
        Path to the PFX on the local computer.

    .PARAMETER Password
        PFX password.

    .PARAMETER ReadAccessAccount
        Account or group names to grant Read access to the private key.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [Parameter(Mandatory)]
        [string]$PfxPath,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [securestring]$Password,
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$ReadAccessAccount
    )

    if (-not (Test-Path -LiteralPath $PfxPath -PathType Leaf)) {
        throw "PFX file not found: $PfxPath"
    }
    if (@($ReadAccessAccount | Where-Object { -not $_.Trim() }).Count -gt 0) {
        throw 'ReadAccessAccount cannot contain empty account names.'
    }

    $sRemoteTemp = Invoke-Command -Session $Session -ScriptBlock {
        Join-Path $env:TEMP ("certpush_" + [Guid]::NewGuid().ToString('N') + '.pfx')
    }
    Copy-Item -LiteralPath $PfxPath -Destination $sRemoteTemp -ToSession $Session -Force
    try {
        $oResult = Invoke-Command -Session $Session -ArgumentList $sRemoteTemp, $Password, ($ReadAccessAccount -join "`n") -ScriptBlock {
            param($PfxPath, [System.Security.SecureString]$Password, $ReadAccessAccountText)
            $hResult = [ordered]@{
                Success = $false
                Error = $null
                Thumbprint = $null
                Subject = $null
                Store = 'Cert:\LocalMachine\My'
                KeyExportable = $false
                KeyStorage = $null
                ReadAccess = @()
            }
            $oPfx = $null
            $oPrivateKey = $null
            try {
                $hAccessBySid = @{}
                foreach ($sAccount in ($ReadAccessAccountText -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
                    if ($sAccount.StartsWith('.\')) {
                        $sAccount = $env:COMPUTERNAME + $sAccount.Substring(1)
                    }
                    $oSid = (New-Object System.Security.Principal.NTAccount($sAccount)).Translate(
                        [System.Security.Principal.SecurityIdentifier])
                    if (-not $hAccessBySid.ContainsKey($oSid.Value)) {
                        $hAccessBySid[$oSid.Value] = [PSCustomObject]@{ Account = $sAccount; SID = $oSid }
                    }
                }
                if ($hAccessBySid.Count -eq 0) { throw 'At least one account or group is required.' }

                $pBSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
                try {
                    $sPlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($pBSTR)
                } finally {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pBSTR)
                }

                $eFlags = [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::MachineKeySet -bor
                    [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
                $oPfx = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                $oPfx.Import($PfxPath, $sPlainPassword, $eFlags)
                $oLeaf = @($oPfx | Where-Object { $_.HasPrivateKey } | Select-Object -First 1)[0]
                if (-not $oLeaf) { throw 'The PFX does not contain a private key.' }

                $oPrivateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($oLeaf)
                if (-not $oPrivateKey) {
                    $oPrivateKey = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($oLeaf)
                }
                if (-not $oPrivateKey) { throw 'The private-key provider is not supported.' }

                $sKeyName = $null
                if ($oPrivateKey.PSObject.Properties['Key'] -and $oPrivateKey.Key.UniqueName) {
                    $sKeyName = $oPrivateKey.Key.UniqueName
                    $hResult.KeyStorage = 'CNG'
                    if ($oPrivateKey.Key.ExportPolicy -ne [System.Security.Cryptography.CngExportPolicies]::None) {
                        throw 'The imported CNG private key is exportable; installation was stopped.'
                    }
                } elseif ($oPrivateKey.PSObject.Properties['CspKeyContainerInfo']) {
                    $sKeyName = $oPrivateKey.CspKeyContainerInfo.UniqueKeyContainerName
                    $hResult.KeyStorage = 'CAPI'
                    if ($oPrivateKey.CspKeyContainerInfo.Exportable) {
                        throw 'The imported CAPI private key is exportable; installation was stopped.'
                    }
                } else {
                    throw 'The private-key provider does not expose a verifiable export policy.'
                }

                $sKeyFile = $null
                foreach ($sDirectory in 'Microsoft\Crypto\Keys', 'Microsoft\Crypto\RSA\MachineKeys', 'Microsoft\Crypto\SystemKeys') {
                    $sCandidate = Join-Path $env:ProgramData "$sDirectory\$sKeyName"
                    if (Test-Path -LiteralPath $sCandidate -PathType Leaf) {
                        $sKeyFile = $sCandidate
                        break
                    }
                }
                if (-not $sKeyFile) { throw 'Private-key file was not found; no certificate was added to the store.' }

                $oAcl = Get-Acl -LiteralPath $sKeyFile
                foreach ($oIdentity in $hAccessBySid.Values) {
                    $bHasReadAccess = $false
                    foreach ($oRule in $oAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
                        if (($oRule.IdentityReference -eq $oIdentity.SID) -and
                            ($oRule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) -and
                            (($oRule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::Read) -eq
                                [System.Security.AccessControl.FileSystemRights]::Read)) {
                            $bHasReadAccess = $true
                            break
                        }
                    }
                    if (-not $bHasReadAccess) {
                        $oAcl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
                            $oIdentity.SID, [System.Security.AccessControl.FileSystemRights]::Read,
                            [System.Security.AccessControl.AccessControlType]::Allow)))
                    }
                    $hResult.ReadAccess += [PSCustomObject]@{
                        Account = $oIdentity.Account
                        SID = $oIdentity.SID.Value
                        Status = if ($bHasReadAccess) { 'AlreadyGranted' } else { 'Granted' }
                    }
                }
                Set-Acl -LiteralPath $sKeyFile -AclObject $oAcl

                $oMyStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('My', 'LocalMachine')
                $oMyStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                try { $oMyStore.Add($oLeaf) } finally { $oMyStore.Close() }

                $aIntermediates = @($oPfx | Where-Object { -not $_.HasPrivateKey -and $_.Subject -ne $_.Issuer })
                if ($aIntermediates.Count -gt 0) {
                    $oCaStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('CA', 'LocalMachine')
                    $oCaStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                    try { foreach ($oCA in $aIntermediates) { $oCaStore.Add($oCA) } } finally { $oCaStore.Close() }
                }

                $hResult.Thumbprint = $oLeaf.Thumbprint.ToUpperInvariant()
                $hResult.Subject = $oLeaf.Subject
                $hResult.Success = $true
            } catch {
                $hResult.Error = $_.Exception.Message
            } finally {
                if ($oPrivateKey) { $oPrivateKey.Dispose() }
                if ($oPfx) { foreach ($oCertificate in $oPfx) { $oCertificate.Dispose() } }
            }
            [PSCustomObject]$hResult
        }
    } finally {
        Invoke-Command -Session $Session -ArgumentList $sRemoteTemp -ScriptBlock {
            param($Path)
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        }
    }
    $oResult | Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
}
