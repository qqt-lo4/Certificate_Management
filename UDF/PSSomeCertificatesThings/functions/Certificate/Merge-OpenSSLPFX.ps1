function Merge-OpenSSLPFX {
<#
.SYNOPSIS
    Merges a private key, certificate, and certificate chain into a PFX file

.DESCRIPTION
    Creates a PFX (PKCS#12) file by merging a private key, certificate, intermediate CA certificate(s),
    and root CA certificate using OpenSSL. Supports password protection, Windows-compatible PFX format,
    CSP specification, and friendly names.

.PARAMETER Cert
    Path to the certificate file.

.PARAMETER IntermediateCA
    Path to the intermediate CA certificate file.

.PARAMETER RootCA
    Path to the root CA certificate file.

.PARAMETER PrivateKey
    Path to the private key file.

.PARAMETER PFXPassword
    SecureString password to protect the PFX file.

.PARAMETER KeyPassword
    SecureString password for the private key file (if encrypted).

.PARAMETER OpenSSLPath
    Path to OpenSSL executable or directory containing openssl.exe. If not specified, searches in PATH.

.PARAMETER OutPFXFile
    Output path for the PFX file. Default: temp folder with timestamp.

.PARAMETER WindowsPFX
    If specified, creates a Windows-compatible PFX using PBE-SHA1-3DES encryption.

.PARAMETER CSP
    Cryptographic Service Provider to specify in the PFX.

.PARAMETER FriendlyName
    Friendly name for the certificate in the PFX.

.OUTPUTS
    None. Creates a PFX file at the specified output path.

.EXAMPLE
    Merge-OpenSSLPFX -Cert "C:\Certs\cert.cer" -PrivateKey "C:\Keys\private.key" -RootCA "C:\Certs\root.cer" -OutPFXFile "C:\Certs\cert.pfx"

.EXAMPLE
    $pfxPwd = ConvertTo-SecureString "MyPassword123" -AsPlainText -Force
    Merge-OpenSSLPFX -Cert "cert.cer" -PrivateKey "key.key" -IntermediateCA "intermediate.cer" -RootCA "root.cer" -PFXPassword $pfxPwd -WindowsPFX -FriendlyName "My Certificate"

.EXAMPLE
    $keyPwd = ConvertTo-SecureString "KeyPassword" -AsPlainText -Force
    $pfxPwd = ConvertTo-SecureString "PFXPassword" -AsPlainText -Force
    Merge-OpenSSLPFX -Cert "cert.cer" -PrivateKey "encrypted-key.key" -RootCA "root.cer" -KeyPassword $keyPwd -PFXPassword $pfxPwd -CSP "Microsoft Enhanced RSA and AES Cryptographic Provider"

.PARAMETER CertificateFiles
    AutoChain mode: one or more paths to certificate files (any mix of CER/CRT/P7B,
    in any order). The chain is reconstructed via Get-CertificateChain — the leaf is
    used in place of -Cert and the rest of the chain replaces -IntermediateCA / -RootCA.
    Mutually exclusive with -Cert / -IntermediateCA / -RootCA.

.PARAMETER IncludeOSStore
    AutoChain mode: forwarded to Get-CertificateChain. When set, missing intermediates
    or root are looked up in the Windows certificate stores (CA / Root / AuthRoot in
    LocalMachine and CurrentUser scope).

.NOTES
    Author  : Loïc Ade
    Version : 1.1.0

    CHANGELOG:

    Version 1.1.0 - 2026-04-26 - Loïc Ade
        - Added AutoChain parameter set (-CertificateFiles) which delegates chain
          reconstruction to Get-CertificateChain and writes temporary PEM files for the
          leaf and the rest of the chain before invoking openssl. Fails fast when the
          chain does not terminate on a self-signed root.
        - Forwarded -IncludeOSStore to Get-CertificateChain so missing intermediates /
          root can be resolved from the Windows certificate stores.

    Version 1.0.0 - Loïc Ade
        - Initial release
#>

    [CmdletBinding(DefaultParameterSetName = "Explicit")]
    Param(
        [Parameter(ParameterSetName = "Explicit")]
        [ValidateScript({
            if($_ -and (-not (Test-Path -Path $_ -PathType Leaf))){
                throw "Cert file does not exist"
            }
            return $true
        })]
        [string]$Cert,
        [Parameter(ParameterSetName = "Explicit")]
        [ValidateScript({
            if($_ -and (-not (Test-Path -Path $_ -PathType Leaf))){
                throw "Intermediate CA cert file does not exist"
            }
            return $true
        })]
        [string]$IntermediateCA,
        [Parameter(ParameterSetName = "Explicit")]
        [ValidateScript({
            if($_ -and (-not (Test-Path -Path $_ -PathType Leaf))){
                throw "Root CA cert file does not exist"
            }
            return $true
        })]
        [string]$RootCA,
        [Parameter(ParameterSetName = "AutoChain", Mandatory)]
        [ValidateScript({
            foreach ($p in $_) {
                if (-not (Test-Path -Path $p -PathType Leaf)) { throw "Certificate file does not exist: $p" }
            }
            return $true
        })]
        [string[]]$CertificateFiles,
        [Parameter(ParameterSetName = "AutoChain")]
        [switch]$IncludeOSStore,
        [ValidateScript({
            if($_ -and (-not (Test-Path -Path $_ -PathType Leaf))){
                throw "Private Key file does not exist"
            }
            return $true
        })]
        [string]$PrivateKey,
        [securestring]$PFXPassword,
        [securestring]$KeyPassword,
        [string]$OpenSSLPath,
        [string]$OutPFXFile = ($env:TEMP + "\" + (Get-Date -Format "yyyyMMdd_HHmmss") + "_outpfx.pfx"),
        [switch]$WindowsPFX,
        [string]$CSP,
        [string]$FriendlyName
    )

    # Resolve $sLeafPath (leaf cert file passed as -in) and $sChainPath (concatenated
    # intermediates+root passed as -certfile, or empty when there is no chain). Both
    # modes feed into the same openssl call below. We cannot reuse the $Cert parameter
    # itself because PowerShell re-runs its [ValidateScript] on every internal
    # assignment, and the temp file written by AutoChain does not exist yet at that
    # point.
    $aTempFiles = @()
    $sLeafPath = $Cert
    $sChainPath = ""
    if ($PSCmdlet.ParameterSetName -eq "AutoChain") {
        # Reconstruct the chain from the unordered files: write the leaf as -in, and the
        # rest of the chain (intermediates first, root last) as -certfile.
        $aChain = Get-CertificateChain -CertificateFiles $CertificateFiles -IncludeOSStore:$IncludeOSStore
        $sStamp = Get-Date -Format "yyyyMMdd_HHmmssfff"
        $sLeafPath = Join-Path $env:TEMP "pfxleaf_$sStamp.cer"
        ConvertTo-PEMCertificate -Certificate $aChain[0] | Out-File -FilePath $sLeafPath -Encoding ascii
        $aTempFiles += $sLeafPath
        if ($aChain.Count -gt 1) {
            $aRest = $aChain[1..($aChain.Count - 1)]
            $sChainPath = Join-Path $env:TEMP "pfxchain_$sStamp.cer"
            ($aRest | ForEach-Object { ConvertTo-PEMCertificate -Certificate $_ }) -join "" |
                Out-File -FilePath $sChainPath -Encoding ascii
            $aTempFiles += $sChainPath
        }
    } elseif ($RootCA) {
        # Explicit mode with a root: combine root + intermediate into a chain file (or
        # use the root file as-is when no intermediate was supplied).
        if ($IntermediateCA) {
            $sIntermediateCA = Get-Content -Path $IntermediateCA
            $sRootCA = Get-Content -Path $RootCA
            $sChainPath = ($env:TEMP + "\" + (Get-Date -Format "yyyyMMdd_HHmmss") + "_chain.pem")
            $sRootCA + $sIntermediateCA | Out-File $sChainPath -Encoding utf8
            $aTempFiles += $sChainPath
        } else {
            $sChainPath = $RootCA
        }
    }

    function Get-OpenSSLPath {
        Param(
            [string]$Inputpath
        )
        if ($Inputpath) {
            if (Test-Path $InputPath -PathType Leaf) {
                return $Inputpath
            } elseif (Test-Path ($Inputpath + "\openssl.exe")) {
                return $Inputpath + "\openssl.exe"
            } else {
                return ""
            }
        } else {
            try {
                return (Get-Command openssl).Source
            } catch {
                return "" 
            }
        }
    }

    try {
        # Find OpenSSL
        $openSSL = Get-OpenSSLPath $OpenSSLPath

        # Build $aOpenSSLArgs array
        $aOpenSSLArgs = @("pkcs12", "-export")
        if ($PFXPassword) {
            if ($WindowsPFX.IsPresent) {
                $aOpenSSLArgs += @("-keypbe", "PBE-SHA1-3DES", "-certpbe", "PBE-SHA1-3DES", "-macalg", "sha1")
            }
        } else {
            $aOpenSSLArgs += @("-keypbe", "NONE", "-certpbe", "NONE", "-nomaciter")
        }
        $sPFXPass = if ($PFXPassword) {
            [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($PFXPassword))
        } else {
            ""
        }
        $aOpenSSLArgs += @("-passout", "pass:$sPFXPass", "-inkey", $PrivateKey)
        if ($KeyPassword) {
            $sKeyPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeyPassword))
            $aOpenSSLArgs += @("-passin", "pass:$sKeyPass")
        }
        $aOpenSSLArgs += @("-out", $OutPFXFile, "-in", $sLeafPath)
        if ($sChainPath -ne "") {
            $aOpenSSLArgs += @("-certfile", $sChainPath)
        }

        # add friendly name
        if ($FriendlyName) {
            $aOpenSSLArgs += @("-name", $FriendlyName)
        }

        # add CSP
        if ($CSP) {
            $aOpenSSLArgs += @("-CSP", $CSP)
        }

        # call openssl
        if (-not $PFXPassword) {
            Write-Warning "Output PFX not encrypted. Please use -PFXPassword to protect private key by a password."
        }
        Write-Verbose -Message ("openssl " + ([System.String]::Join(" ", $aOpenSSLArgs)))
        &$openssl $aOpenSSLArgs
    } finally {
        foreach ($p in $aTempFiles) {
            if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
        }
    }
}