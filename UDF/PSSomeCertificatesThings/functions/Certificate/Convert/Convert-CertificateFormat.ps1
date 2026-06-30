function Convert-CertificateFormat {
    <#
    .SYNOPSIS
        Converts a PFX (PKCS#12) into other certificate / key output formats

    .DESCRIPTION
        Reads a source PFX and writes the requested output format(s) to a folder. .NET handles
        certificate loading, chain ordering, DER export, PEM certificate export and PFX
        assembly (X509Certificate2Collection.Export). Private key extraction (PKCS#1 / PKCS#8,
        encrypted or not) is delegated to ConvertTo-PEMPrivateKey, which uses OpenSSL because
        .NET cannot reliably export a CNG private key imported from a PFX in plaintext.

        Supported containers:
          - PFX          : PKCS#12, encrypted with -OutPfxPassword or unprotected when omitted
          - PEMCombined  : a single .pem holding the certificate chain and (optionally) the key
          - PEMSeparate  : separate .crt / .chain.pem / .fullchain.pem / .key files
          - DER          : binary certificate(s), no private key

        The returned object exposes KeyInClear = $true whenever the produced files contain an
        unencrypted private key (a Plain key, or a PFX without password). The caller is
        expected to wrap such output in a password-protected archive before storing it.

    .PARAMETER PfxPath
        Path to the source PFX file.

    .PARAMETER PfxPassword
        SecureString password of the source PFX (use an empty SecureString when none).

    .PARAMETER OutputDir
        Folder where the output files are written.

    .PARAMETER BaseName
        Base file name (without extension) used for the produced files.

    .PARAMETER Container
        Output container: PFX, PEMCombined, PEMSeparate or DER.

    .PARAMETER IncludeChain
        Include the intermediate CA certificate(s) in the output.

    .PARAMETER IncludeRoot
        Include the root CA certificate in the output.

    .PARAMETER IncludeKey
        Include the private key (ignored for the DER container).

    .PARAMETER KeyFormat
        Private key PEM structure: PKCS8 (default) or PKCS1. Applies to PEM containers.

    .PARAMETER KeyEncryption
        Private key protection for PEM containers: Plain (default) or Encrypt. Encrypt
        requires -OutKeyPassword and is produced through OpenSSL.

    .PARAMETER OutKeyPassword
        SecureString password for the encrypted PEM private key (KeyEncryption = Encrypt).

    .PARAMETER OutPfxPassword
        SecureString password for the output PFX container. When omitted, the PFX is
        unprotected and KeyInClear is reported as $true.

    .PARAMETER OpenSSLPath
        Path to openssl.exe (required only when KeyEncryption = Encrypt).

    .OUTPUTS
        [pscustomobject] with properties: Files [string[]], KeyInClear [bool].

    .EXAMPLE
        Convert-CertificateFormat -PfxPath cert.pfx -PfxPassword $src -OutputDir C:\out `
            -BaseName www -Container PEMSeparate -IncludeChain -IncludeKey -KeyFormat PKCS8

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-06-21 - Loïc Ade
            - Initial release
            - .NET for load / chain ordering / DER / PEM cert / PFX assembly
            - Private key (PKCS#1 / PKCS#8, plain or encrypted) via ConvertTo-PEMPrivateKey (OpenSSL)
            - Reports KeyInClear so the caller can enforce an encrypted archive
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    Param(
        [Parameter(Mandatory)]
        [ValidateScript({ if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "PFX file does not exist: $_" } return $true })]
        [string]$PfxPath,
        [securestring]$PfxPassword,
        [Parameter(Mandatory)]
        [string]$OutputDir,
        [Parameter(Mandatory)]
        [string]$BaseName,
        [Parameter(Mandatory)]
        [ValidateSet("PFX", "PEMCombined", "PEMSeparate", "DER")]
        [string]$Container,
        [switch]$IncludeChain,
        [switch]$IncludeRoot,
        [switch]$IncludeKey,
        [ValidateSet("PKCS8", "PKCS1")]
        [string]$KeyFormat = "PKCS8",
        [ValidateSet("Plain", "Encrypt")]
        [string]$KeyEncryption = "Plain",
        [securestring]$OutKeyPassword,
        [securestring]$OutPfxPassword,
        [string]$OpenSSLPath
    )

    function ConvertFrom-SecureStringPlain {
        Param([securestring]$Secure)
        if (-not $Secure) { return "" }
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure))
    }

    if (-not (Test-Path -LiteralPath $OutputDir -PathType Container)) {
        New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
    }

    $aOutFiles = New-Object System.Collections.Generic.List[string]
    $aTempFiles = New-Object System.Collections.Generic.List[string]
    $sSrcPwd = ConvertFrom-SecureStringPlain -Secure $PfxPassword

    try {
        # ---- Load source PFX (exportable so the key can be re-exported) --------------------
        $oCol = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        $oCol.Import($PfxPath, $sSrcPwd, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        $aAll = @($oCol)
        if ($aAll.Count -eq 0) { throw "No certificate found in the PFX." }

        # ---- Identify leaf (the cert carrying the private key) -----------------------------
        $oLeaf = $aAll | Where-Object { $_.HasPrivateKey } | Select-Object -First 1
        if (-not $oLeaf) {
            # Fallback: the cert that is not a parent of any other in the set.
            $oLeaf = $aAll | Where-Object {
                $oCandidate = $_
                -not ($aAll | Where-Object { Test-CertificateIsParent -Parent $oCandidate -Child $_ })
            } | Select-Object -First 1
        }
        if (-not $oLeaf) { throw "Unable to identify the leaf certificate in the PFX." }

        # ---- Order the chain leaf -> root --------------------------------------------------
        $aChain = New-Object System.Collections.Generic.List[object]
        $aChain.Add($oLeaf)
        $oCurrent = $oLeaf
        $hVisited = @{ $oLeaf.Thumbprint = $true }
        while ($oCurrent.Subject -ne $oCurrent.Issuer) {
            $oParent = $aAll | Where-Object {
                -not $hVisited.ContainsKey($_.Thumbprint) -and (Test-CertificateIsParent -Parent $_ -Child $oCurrent)
            } | Select-Object -First 1
            if (-not $oParent) { break }   # chain incomplete in the PFX; keep what we have
            $aChain.Add($oParent)
            $hVisited[$oParent.Thumbprint] = $true
            $oCurrent = $oParent
        }

        $oRoot = if ($aChain.Count -gt 0 -and $aChain[$aChain.Count - 1].Subject -eq $aChain[$aChain.Count - 1].Issuer) {
            $aChain[$aChain.Count - 1]
        } else { $null }

        $aIntermediates = @($aChain | Where-Object {
            $_.Thumbprint -ne $oLeaf.Thumbprint -and (-not $oRoot -or $_.Thumbprint -ne $oRoot.Thumbprint)
        })

        # ---- Certificates selected for cert outputs ---------------------------------------
        $aSelectedCerts = New-Object System.Collections.Generic.List[object]
        $aSelectedCerts.Add($oLeaf)
        if ($IncludeChain) { foreach ($c in $aIntermediates) { $aSelectedCerts.Add($c) } }
        if ($IncludeRoot -and $oRoot) { $aSelectedCerts.Add($oRoot) }

        # ---- Build the private key PEM (delegated to ConvertTo-PEMPrivateKey) --------------
        $sKeyPem = $null
        if ($IncludeKey -and $Container -ne "DER") {
            if (-not $OpenSSLPath) { throw "OpenSSLPath is required to export the private key." }
            $hKeyParams = @{
                PfxPath     = $PfxPath
                PfxPassword = $PfxPassword
                Format      = $KeyFormat
                OpenSSLPath = $OpenSSLPath
            }
            if ($KeyEncryption -eq "Encrypt") {
                if (-not $OutKeyPassword) { throw "OutKeyPassword is required when KeyEncryption is Encrypt." }
                $hKeyParams.Password = $OutKeyPassword
            }
            $sKeyPem = ConvertTo-PEMPrivateKey @hKeyParams
        }

        # ---- Produce the output container --------------------------------------------------
        switch ($Container) {
            "DER" {
                $sLeafDer = Join-Path $OutputDir "$BaseName.cer"
                [System.IO.File]::WriteAllBytes($sLeafDer, $oLeaf.RawData)
                $aOutFiles.Add($sLeafDer)
                $iIdx = 1
                foreach ($c in @($aSelectedCerts | Select-Object -Skip 1)) {
                    $sCaDer = Join-Path $OutputDir ("{0}.ca{1}.cer" -f $BaseName, $iIdx)
                    [System.IO.File]::WriteAllBytes($sCaDer, $c.RawData)
                    $aOutFiles.Add($sCaDer)
                    $iIdx++
                }
            }
            "PEMCombined" {
                $oSb = New-Object System.Text.StringBuilder
                foreach ($c in $aSelectedCerts) { [void]$oSb.Append((ConvertTo-PEMCertificate -Certificate $c)) }
                if ($sKeyPem) { [void]$oSb.Append($sKeyPem) }
                $sPem = Join-Path $OutputDir "$BaseName.pem"
                [System.IO.File]::WriteAllText($sPem, $oSb.ToString())
                $aOutFiles.Add($sPem)
            }
            "PEMSeparate" {
                $sCrt = Join-Path $OutputDir "$BaseName.crt"
                [System.IO.File]::WriteAllText($sCrt, (ConvertTo-PEMCertificate -Certificate $oLeaf))
                $aOutFiles.Add($sCrt)

                $aCaCerts = @($aSelectedCerts | Select-Object -Skip 1)
                if ($aCaCerts.Count -gt 0) {
                    $sChainContent = ($aCaCerts | ForEach-Object { ConvertTo-PEMCertificate -Certificate $_ }) -join ""
                    $sChain = Join-Path $OutputDir "$BaseName.chain.pem"
                    [System.IO.File]::WriteAllText($sChain, $sChainContent)
                    $aOutFiles.Add($sChain)

                    $sFull = Join-Path $OutputDir "$BaseName.fullchain.pem"
                    [System.IO.File]::WriteAllText($sFull, ((ConvertTo-PEMCertificate -Certificate $oLeaf) + $sChainContent))
                    $aOutFiles.Add($sFull)
                }
                if ($sKeyPem) {
                    $sKeyFile = Join-Path $OutputDir "$BaseName.key"
                    [System.IO.File]::WriteAllText($sKeyFile, $sKeyPem)
                    $aOutFiles.Add($sKeyFile)
                }
            }
            "PFX" {
                $oExportCol = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
                foreach ($c in $aSelectedCerts) { [void]$oExportCol.Add($c) }
                $sPfxPwd = ConvertFrom-SecureStringPlain -Secure $OutPfxPassword
                $aPfxBytes = $oExportCol.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, $sPfxPwd)
                $sPfxOut = Join-Path $OutputDir "$BaseName.pfx"
                [System.IO.File]::WriteAllBytes($sPfxOut, $aPfxBytes)
                $aOutFiles.Add($sPfxOut)
            }
        }

        # ---- Did we just write an unencrypted private key to disk? -------------------------
        $bKeyInClear = $false
        if ($Container -eq "PFX") {
            $bKeyInClear = -not $OutPfxPassword
        } elseif ($IncludeKey -and ($Container -in @("PEMCombined", "PEMSeparate"))) {
            $bKeyInClear = ($KeyEncryption -eq "Plain")
        }

        return [pscustomobject]@{
            Files      = $aOutFiles.ToArray()
            KeyInClear = $bKeyInClear
        }
    } finally {
        foreach ($p in $aTempFiles) {
            if (Test-Path -LiteralPath $p) {
                try {
                    # best-effort overwrite before delete (temp key material)
                    $len = (Get-Item -LiteralPath $p).Length
                    if ($len -gt 0) {
                        $z = New-Object byte[] $len
                        [System.IO.File]::WriteAllBytes($p, $z)
                    }
                } catch {}
                Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
