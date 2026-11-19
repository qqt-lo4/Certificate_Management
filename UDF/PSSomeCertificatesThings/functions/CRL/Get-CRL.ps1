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

    .PARAMETER ReturnRawData
        Return the downloaded DER bytes instead of the platform CRL object.

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
        [int]$DownloadTimeout = 15,
        [switch]$ReturnRawData
    )
    Begin {
        $iTimeout = $DownloadTimeout * 1000

        if (-not ('PSSomeCertificatesThings.Native.Cryptnet' -as [type])) {
            $sNativeSignature = @"
using System;
using System.Runtime.InteropServices;

namespace PSSomeCertificatesThings.Native
{
    public static class Cryptnet
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct CRL_CONTEXT
        {
            public uint dwCertEncodingType;
            public IntPtr pbCrlEncoded;
            public uint cbCrlEncoded;
            public IntPtr pCrlInfo;
            public IntPtr hCertStore;
        }

        [DllImport("cryptnet.dll", EntryPoint = "CryptRetrieveObjectByUrlW", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptRetrieveObjectByUrl(
            string pszUrl,
            IntPtr pszObjectOid,
            uint dwRetrievalFlags,
            uint dwTimeout,
            out IntPtr ppvObject,
            IntPtr hAsyncRetrieve,
            IntPtr pCredentials,
            IntPtr pvVerify,
            IntPtr pAuxInfo);

        [DllImport("crypt32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CertFreeCRLContext(IntPtr pCrlContext);
    }
}
"@
            Add-Type -TypeDefinition $sNativeSignature
        }
    }
    Process {
        $ppvObject = [IntPtr]::Zero
        if ([PSSomeCertificatesThings.Native.Cryptnet]::CryptRetrieveObjectByUrl($URL,[IntPtr]2,4,$iTimeout,[ref]$ppvObject,
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            [IntPtr]::Zero,
            [IntPtr]::Zero)
        ) {
            $oCRLContext = [Runtime.InteropServices.Marshal]::PtrToStructure(
                $ppvObject, [type][PSSomeCertificatesThings.Native.Cryptnet+CRL_CONTEXT])
            $rawData = New-Object byte[] -ArgumentList $oCRLContext.cbCrlEncoded
            [Runtime.InteropServices.Marshal]::Copy($oCRLContext.pbCrlEncoded,$rawData,0,$rawData.Length)
            try {
                if ($ReturnRawData) {
                    Write-Output -NoEnumerate $rawData
                } else {
                    $crl = New-Object Security.Cryptography.X509Certificates.X509CRL2 (,$rawData)
                    Write-Debug "CRL: $($crl.Issuer)"
                    $crl
                }
            } finally {
                [void][PSSomeCertificatesThings.Native.Cryptnet]::CertFreeCRLContext($ppvObject)
            }
        } else {
            $hresult = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $oError = New-Object System.ComponentModel.Win32Exception($hresult)
            throw "CRL retrieval failed for '$URL': $($oError.Message) (Win32 $hresult)."
        }
    }
}