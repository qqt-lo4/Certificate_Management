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

.NOTES
    Author  : Loïc Ade
    Version : 1.0.0
#>

    [CmdletBinding()]
    Param(
        [ValidateScript({
            if($_ -and (-not (Test-Path -Path $_ -PathType Leaf))){
                throw "Cert file does not exist"
            }
            return $true
        })]
        [string]$Cert,
        [ValidateScript({
            if($_ -and (-not (Test-Path -Path $_ -PathType Leaf))){
                throw "Intermediate CA cert file does not exist"
            }
            return $true
        })]
        [string]$IntermediateCA,
        [ValidateScript({
            if($_ -and (-not (Test-Path -Path $_ -PathType Leaf))){
                throw "Root CA cert file does not exist"
            }
            return $true
        })]
        [string]$RootCA,
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

    # Find OpenSSL
    $openSSL = Get-OpenSSLPath $OpenSSLPath

    # Create certificate chain
    $CertChain = if ($RootCA) {
        if ($IntermediateCA) {
            $sIntermediateCA = Get-Content -Path $IntermediateCA
            $sRootCA = Get-Content -Path $RootCA
            $CertChainPath = ($env:TEMP + "\" + (Get-Date -Format "yyyyMMdd_HHmmss") + "_chain.pem")
            $sRootCA + $sIntermediateCA | Out-File $CertChainPath -Encoding utf8
            $CertChainPath
        } else {
            $RootCA
        }
    } else {
        ""
    }
    
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
    $aOpenSSLArgs += @("-out", $OutPFXFile, "-in", $Cert)
    if ($CertChain -ne "") {
        $aOpenSSLArgs += @("-certfile", $CertChain)
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
}