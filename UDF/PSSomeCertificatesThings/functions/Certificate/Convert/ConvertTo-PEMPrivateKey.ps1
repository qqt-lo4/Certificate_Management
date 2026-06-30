function ConvertTo-PEMPrivateKey {
    <#
    .SYNOPSIS
        Extracts the private key of a PFX as a PEM string, in PKCS#1 or PKCS#8 form

    .DESCRIPTION
        Reads the private key from a source PFX (PKCS#12) with OpenSSL and returns it as a PEM
        block, either PKCS#1 ("-----BEGIN RSA PRIVATE KEY-----") or PKCS#8
        ("-----BEGIN PRIVATE KEY-----" / "-----BEGIN ENCRYPTED PRIVATE KEY-----").

        OpenSSL is used rather than the .NET key APIs because importing a PFX in .NET produces
        a CNG key whose plaintext export is blocked for many providers (the Exportable flag
        only grants encrypted export), which makes a pure .NET extraction unreliable across
        the PFX files this tool has to handle. OpenSSL extracts the key consistently.

        When -Password is supplied the key is encrypted (PBES2 AES-256 for PKCS#8, traditional
        AES-256 for PKCS#1); otherwise it is unencrypted.

    .PARAMETER PfxPath
        Path to the source PFX file.

    .PARAMETER PfxPassword
        SecureString password of the source PFX (use an empty SecureString when none).

    .PARAMETER Format
        PEM key structure: "PKCS8" (default) or "PKCS1".

    .PARAMETER Password
        SecureString password protecting the output key. When supplied, the key is encrypted;
        when omitted, the key is written unencrypted.

    .PARAMETER OpenSSLPath
        Path to openssl.exe.

    .PARAMETER OutFile
        Optional output file. When supplied the PEM is written there (and the path is
        returned); otherwise the PEM is returned as a string.

    .OUTPUTS
        [string]. The PEM block (or the output file path when -OutFile is used).

    .EXAMPLE
        ConvertTo-PEMPrivateKey -PfxPath cert.pfx -PfxPassword $src -OpenSSLPath $openssl |
            Out-File key.pem -Encoding ascii

    .EXAMPLE
        ConvertTo-PEMPrivateKey -PfxPath cert.pfx -PfxPassword $src -Format PKCS1 `
            -Password $keyPwd -OpenSSLPath $openssl -OutFile www.key

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-06-21 - Loïc Ade
            - Initial release
            - Extracts the private key from a source PFX with OpenSSL (reliable across PFX
              providers, unlike .NET CNG plaintext export)
            - Emits PKCS#1 or PKCS#8, unencrypted or AES-256 encrypted when -Password is set
            - Passwords passed to OpenSSL via environment variables (-pass*=env:), so special
              characters such as " and $ survive Windows PowerShell 5.1 native-argument quoting
            - Returns the PEM string, or writes it to -OutFile and returns the path
    #>
    [CmdletBinding()]
    [OutputType([string])]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateScript({ if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "PFX file does not exist: $_" } return $true })]
        [string]$PfxPath,
        [securestring]$PfxPassword,
        [ValidateSet("PKCS8", "PKCS1")]
        [string]$Format = "PKCS8",
        [securestring]$Password,
        [Parameter(Mandatory)]
        [ValidateScript({ if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "openssl.exe not found: $_" } return $true })]
        [string]$OpenSSLPath,
        [string]$OutFile
    )

    function ConvertFrom-SecureStringPlain {
        Param([securestring]$Secure)
        if (-not $Secure) { return "" }
        return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure))
    }

    $sSrcPwd = ConvertFrom-SecureStringPlain -Secure $PfxPassword
    $sOutPwd = ConvertFrom-SecureStringPlain -Secure $Password
    $bEncrypt = [bool]$sOutPwd

    $sStamp = Get-Date -Format "yyyyMMdd_HHmmssfff"
    $sTmpPlain = Join-Path $env:TEMP "pemkeyplain_$sStamp.pem"
    $sTmpKey   = Join-Path $env:TEMP "pemkey_$sStamp.pem"
    $aTempFiles = @($sTmpPlain, $sTmpKey)

    # Pass passwords to OpenSSL through environment variables (-pass*=env:VAR) rather than on
    # the command line (pass:...): Windows PowerShell 5.1 mangles native-command arguments that
    # contain double quotes, which would corrupt the password. The env vars are cleared in the
    # finally block. (Also keeps the password out of the visible process command line.)
    $env:PSCERT_PFXIN = $sSrcPwd
    try {
        # 1. Extract the unencrypted key from the PFX.
        & $OpenSSLPath pkcs12 -in $PfxPath -nocerts -nodes -passin env:PSCERT_PFXIN -out $sTmpPlain 2>&1 | Out-Null
        if (-not (Test-Path -LiteralPath $sTmpPlain -PathType Leaf) -or (Get-Item -LiteralPath $sTmpPlain).Length -eq 0) {
            throw "OpenSSL failed to extract the private key from the PFX (wrong password?)."
        }

        # 2. Convert to the requested format / encryption.
        if ($bEncrypt) {
            $env:PSCERT_KEYOUT = $sOutPwd
            if ($Format -eq "PKCS8") {
                & $OpenSSLPath pkcs8 -topk8 -in $sTmpPlain -passout env:PSCERT_KEYOUT -out $sTmpKey 2>&1 | Out-Null
            } else {
                & $OpenSSLPath rsa -in $sTmpPlain -aes256 -passout env:PSCERT_KEYOUT -out $sTmpKey 2>&1 | Out-Null
            }
        } else {
            if ($Format -eq "PKCS8") {
                & $OpenSSLPath pkcs8 -topk8 -nocrypt -in $sTmpPlain -out $sTmpKey 2>&1 | Out-Null
            } else {
                & $OpenSSLPath rsa -in $sTmpPlain -out $sTmpKey 2>&1 | Out-Null
            }
        }
        if (-not (Test-Path -LiteralPath $sTmpKey -PathType Leaf) -or (Get-Item -LiteralPath $sTmpKey).Length -eq 0) {
            throw "OpenSSL failed to produce the private key in $Format format."
        }

        $sKeyPem = Get-Content -LiteralPath $sTmpKey -Raw
        if (-not $sKeyPem.EndsWith("`n")) { $sKeyPem += "`n" }

        if ($OutFile) {
            [System.IO.File]::WriteAllText($OutFile, $sKeyPem)
            return $OutFile
        }
        return $sKeyPem
    } finally {
        Remove-Item Env:\PSCERT_PFXIN -ErrorAction SilentlyContinue
        Remove-Item Env:\PSCERT_KEYOUT -ErrorAction SilentlyContinue
        foreach ($p in $aTempFiles) {
            if (Test-Path -LiteralPath $p) {
                try {
                    $len = (Get-Item -LiteralPath $p).Length
                    if ($len -gt 0) { [System.IO.File]::WriteAllBytes($p, (New-Object byte[] $len)) }
                } catch {}
                Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
