function Get-CRL {
    <#
    .SYNOPSIS
        Downloads and parses a Certificate Revocation List from a URL

    .DESCRIPTION
        Retrieves a Certificate Revocation List (CRL) from a given URL using CryptRetrieveObjectByUrl
        from cryptnet.dll. Parses the CRL data and returns an X509CRL2 object.

    .PARAMETER URL
        URL of the CRL to download.

    .PARAMETER DownloadTimeout
        Timeout in seconds for the download operation. Default: 15.

    .OUTPUTS
        [Security.Cryptography.X509Certificates.X509CRL2]. The downloaded and parsed CRL object, or error message if download fails.

    .EXAMPLE
        Get-CRL -URL "http://crl.example.com/crl/ca.crl"

    .EXAMPLE
        Get-CRL -URL "http://pki.company.com/crl.crl" -DownloadTimeout 30

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$URL,
        [int]$DownloadTimeout = 15
    )
    Begin {
        function Test-Type {
            Param(
                [Parameter(Mandatory, Position = 0)]
                [ValidatePattern("^[a-zA-Z_.0-9-]+$")]
                [string]$TypeName
            )
            try {
                Invoke-Expression -Command "[$TypeName] -as [type]" | Out-Null
                return $true
            } catch {
                return $false
            }
        }

        $iTimeout = $DownloadTimeout * 1000

        if (-not (Test-Type "Cryptnet.Func_CryptRetrieveObjectByUrl")) {
            $cryptnetsignature = @"
            [DllImport("cryptnet.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CryptRetrieveObjectByUrl(
                //[MarshalAs(UnmanagedType.LPStr)]
                string pszUrl,
                //[MarshalAs(UnmanagedType.LPStr)]
                int pszObjectOid,
                int dwRetrievalFlags,
                int dwTimeout,
                ref IntPtr ppvObject,
                IntPtr hAsyncRetrieve,
                IntPtr pCredentials,
                IntPtr pvVerify,
                IntPtr pAuxInfo
            );
"@
            Add-Type -MemberDefinition $cryptnetsignature -Namespace "Cryptnet" -Name "Func_CryptRetrieveObjectByUrl"
        }

    }
    Process {
        $ppvObject = [IntPtr]::Zero
        if ([PKI.EnterprisePKI.Cryptnet]::CryptRetrieveObjectByUrl($URL,2,4,$iTimeout,[ref]$ppvObject,
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            [IntPtr]::Zero)
        ) {
            $crlContext = [Runtime.InteropServices.Marshal]::PtrToStructure($ppvObject,[Type][PKI.EnterprisePKI.Crypt32+CRL_CONTEXT])
            $rawData = New-Object byte[] -ArgumentList $crlContext.cbCrlEncoded
            [Runtime.InteropServices.Marshal]::Copy($crlContext.pbCrlEncoded,$rawData,0,$rawData.Length)
            $crl = New-Object Security.Cryptography.X509Certificates.X509CRL2 (,$rawData)
            Write-Debug "CRL: $($crl.Issuer)"
            $crl
            [void][PKI.EnterprisePKI.Crypt32]::CertFreeCRLContext($ppvObject)
        } else {
            $hresult = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Debug "URL error: $hresult"
            $CertRequest = New-Object -ComObject CertificateAuthority.Request
            $CertRequest.GetErrorMessageText($hresult,0)
            [PKI.Utils.CryptographyUtils]::ReleaseCom($CertRequest)
        }
    }
}