function Get-CRL {
    <#
    .SYNOPSIS
        Downloads a CRL and returns its decoded health information.

    .DESCRIPTION
        Downloads a CRL using CryptRetrieveObjectByUrl.

        Decoding, issuer lookup and health evaluation are delegated to:
            Get-CRLHealthData

        NextPublish extraction uses the existing external helpers:
            Read-DerElement
            Get-DerChildren
            ConvertFrom-DerObjectIdentifier
            ConvertFrom-DerTime

    .PARAMETER URL
        URL of the CRL to download.

    .PARAMETER DownloadTimeout
        Download timeout in seconds. Default: 15.

    .PARAMETER ReturnRawData
        Returns only the downloaded DER bytes.

    .PARAMETER Certificates
        Issuer certificate candidates.

        Accepts X509Certificate2 objects or objects containing
        a Certificate property holding an X509Certificate2.

    .PARAMETER ExpectedType
        Expected CRL type.
        Auto uses the decoded CRL type.

    .PARAMETER WarningRemainingPercent
        Forwarded to Get-CRLHealthData.

    .PARAMETER CriticalRemainingPercent
        Forwarded to Get-CRLHealthData.

    .OUTPUTS
        System.Byte[] with ReturnRawData.
        PSCustomObject otherwise.

    .NOTES
        Requires Windows and the external functions listed above.

        Supplied issuer certificates are not disposed by this function.

        NextPublish is returned in UTC.
        An absent NextPublish extension returns $null.
        A malformed NextPublish extension raises an error.
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$URL,

        [ValidateRange(1, 120)]
        [int]$DownloadTimeout = 15,

        [switch]$ReturnRawData,

        [AllowEmptyCollection()]
        [object[]]$Certificates = @(),

        [ValidateSet('Auto', 'Base', 'Delta')]
        [string]$ExpectedType = 'Auto',

        [ValidateRange(1, 99)]
        [int]$WarningRemainingPercent = 5,

        [ValidateRange(0, 98)]
        [int]$CriticalRemainingPercent = 2
    )

    Begin {
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

        [DllImport(
            "cryptnet.dll",
            EntryPoint = "CryptRetrieveObjectByUrlW",
            CharSet = CharSet.Unicode,
            SetLastError = true)]
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
        public static extern bool CertFreeCRLContext(
            IntPtr pCrlContext);
    }
}
"@

            Add-Type -TypeDefinition $sNativeSignature -ErrorAction Stop
        }
    }

    Process {
        if (
            -not $ReturnRawData -and
            $CriticalRemainingPercent -ge $WarningRemainingPercent
        ) {
            throw (
                'CriticalRemainingPercent must be lower than ' +
                'WarningRemainingPercent.'
            )
        }

        $pCRLContext = [System.IntPtr]::Zero
        $aRawData = $null
        $iTimeoutMilliseconds = $DownloadTimeout * 1000

        # ------------------------------------------------------------
        # 1. Download and copy the native bytes.
        # ------------------------------------------------------------

        try {
            $bRetrieved =
                [PSSomeCertificatesThings.Native.Cryptnet]::CryptRetrieveObjectByUrl(
                    $URL,
                    [System.IntPtr]2,
                    4,
                    $iTimeoutMilliseconds,
                    [ref]$pCRLContext,
                    [System.IntPtr]::Zero,
                    [System.IntPtr]::Zero,
                    [System.IntPtr]::Zero,
                    [System.IntPtr]::Zero
                )

            if (-not $bRetrieved) {
                $iError =
                    [Runtime.InteropServices.Marshal]::GetLastWin32Error()

                $oError =
                    [System.ComponentModel.Win32Exception]::new($iError)

                throw (
                    "CRL retrieval failed for '$URL': " +
                    "$($oError.Message) (error $iError)."
                )
            }

            if ($pCRLContext -eq [System.IntPtr]::Zero) {
                throw 'CRL retrieval returned an empty context.'
            }

            $oContext =
                [Runtime.InteropServices.Marshal]::PtrToStructure(
                    $pCRLContext,
                    [type][PSSomeCertificatesThings.Native.Cryptnet+CRL_CONTEXT]
                )

            if (
                $oContext.cbCrlEncoded -eq 0 -or
                $oContext.cbCrlEncoded -gt [System.Int32]::MaxValue -or
                $oContext.pbCrlEncoded -eq [System.IntPtr]::Zero
            ) {
                throw 'CRL context contains invalid encoded data.'
            }

            $aRawData = New-Object byte[] (
                [int]$oContext.cbCrlEncoded
            )

            [Runtime.InteropServices.Marshal]::Copy(
                $oContext.pbCrlEncoded,
                $aRawData,
                0,
                $aRawData.Length
            )
        }
        finally {
            if ($pCRLContext -ne [System.IntPtr]::Zero) {
                [void][PSSomeCertificatesThings.Native.Cryptnet]::CertFreeCRLContext(
                    $pCRLContext
                )
            }
        }

        if ($ReturnRawData) {
            Write-Output -NoEnumerate $aRawData
        }
        else {
            # --------------------------------------------------------
            # 2. Shared decoding and health evaluation.
            # --------------------------------------------------------

            $hHealthParameters = @{
                RawData                  = $aRawData
                Certificates             = $Certificates
                ExpectedType             = $ExpectedType
                WarningRemainingPercent  = $WarningRemainingPercent
                CriticalRemainingPercent = $CriticalRemainingPercent
                ErrorAction              = 'Stop'
            }

            $oCRLData = Get-CRLHealthData @hHealthParameters

            if ($null -eq $oCRLData) {
                throw 'Get-CRLHealthData returned no result.'
            }

            # --------------------------------------------------------
            # 3. Extract NextPublish if not exposed by the decoder.
            # --------------------------------------------------------

            $dtNextPublish = $null

            if ($null -ne $oCRLData.PSObject.Properties['NextPublish']) {
                $dtNextPublish = $oCRLData.NextPublish
            }

            if ($null -eq $dtNextPublish) {
                $oOuter = Read-DerElement `
                    -Data $aRawData `
                    -Offset 0 `
                    -ErrorAction Stop

                if (
                    $oOuter.Tag -ne 0x30 -or
                    $oOuter.End -ne $aRawData.Length
                ) {
                    throw 'Invalid DER CertificateList.'
                }

                $aOuterParts = @(
                    Get-DerChildren `
                        -Data $aRawData `
                        -Parent $oOuter `
                        -ErrorAction Stop
                )

                if ($aOuterParts.Count -ne 3) {
                    throw 'Malformed DER CertificateList: expected 3 elements.'
                }

                if (
                    $aOuterParts[0].Tag -ne 0x30 -or
                    $aOuterParts[1].Tag -ne 0x30 -or
                    $aOuterParts[2].Tag -ne 0x03
                ) {
                    throw 'Malformed DER CertificateList: unexpected tags.'
                }

                $aTbsParts = @(
                    Get-DerChildren `
                        -Data $aRawData `
                        -Parent $aOuterParts[0] `
                        -ErrorAction Stop
                )

                $aExtensionWrappers = @(
                    $aTbsParts |
                        Where-Object { $_.Tag -eq 0xA0 }
                )

                if ($aExtensionWrappers.Count -gt 1) {
                    throw 'Multiple CRL extension wrappers.'
                }

                if ($aExtensionWrappers.Count -eq 1) {
                    $aWrapperParts = @(
                        Get-DerChildren `
                            -Data $aRawData `
                            -Parent $aExtensionWrappers[0] `
                            -ErrorAction Stop
                    )

                    if ($aWrapperParts.Count -ne 1) {
                        throw 'Malformed CRL extensions wrapper.'
                    }

                    if ($aWrapperParts[0].Tag -ne 0x30) {
                        throw 'CRL extensions must be encoded as a SEQUENCE.'
                    }

                    $bNextPublishFound = $false

                    foreach ($oExtension in (
                        Get-DerChildren `
                            -Data $aRawData `
                            -Parent $aWrapperParts[0] `
                            -ErrorAction Stop
                    )) {
                        if ($oExtension.Tag -ne 0x30) {
                            throw 'Malformed CRL extension entry.'
                        }

                        $aParts = @(
                            Get-DerChildren `
                                -Data $aRawData `
                                -Parent $oExtension `
                                -ErrorAction Stop
                        )

                        if ($aParts.Count -lt 2) {
                            throw 'Incomplete CRL extension.'
                        }

                        if ($aParts[0].Tag -ne 0x06) {
                            throw 'Malformed CRL extension identifier.'
                        }

                        $sOid = ConvertFrom-DerObjectIdentifier `
                            -Data $aRawData `
                            -Element $aParts[0] `
                            -ErrorAction Stop

                        if ($sOid -ne '1.3.6.1.4.1.311.21.4') {
                            continue
                        }

                        if ($bNextPublishFound) {
                            throw 'Duplicate Next CRL Publish extension.'
                        }

                        $bNextPublishFound = $true
                        $iValueIndex = 1

                        # Optional critical BOOLEAN.
                        if ($aParts[$iValueIndex].Tag -eq 0x01) {
                            if ($aParts[$iValueIndex].Length -ne 1) {
                                throw 'Invalid extension critical BOOLEAN.'
                            }

                            $iValueIndex++
                        }

                        if ($iValueIndex -ge $aParts.Count) {
                            throw 'Missing Next CRL Publish extension value.'
                        }

                        if ($aParts.Count -ne ($iValueIndex + 1)) {
                            throw 'Unexpected Next CRL Publish extension fields.'
                        }

                        $oValue = $aParts[$iValueIndex]

                        if (
                            $oValue.Tag -ne 0x04 -or
                            $oValue.Length -eq 0
                        ) {
                            throw 'Invalid Next CRL Publish extension value.'
                        }

                        $oTime = Read-DerElement `
                            -Data $aRawData `
                            -Offset $oValue.ContentStart `
                            -ErrorAction Stop

                        if ($oTime.End -ne $oValue.End) {
                            throw 'Invalid Next CRL Publish time encoding.'
                        }

                        $dtNextPublish = ConvertFrom-DerTime `
                            -Data $aRawData `
                            -Element $oTime `
                            -ErrorAction Stop
                    }
                }
            }

            if ($null -ne $dtNextPublish) {
                $dtNextPublish = (
                    [datetime]$dtNextPublish
                ).ToUniversalTime()
            }

            # --------------------------------------------------------
            # 4. Normalize dates and calculate publication information.
            # --------------------------------------------------------

            $dtNowUtc = [System.DateTime]::UtcNow

            $dtThisUpdate = (
                [datetime]$oCRLData.ThisUpdate
            ).ToUniversalTime()

            $dtNextUpdate = $null

            if ($null -ne $oCRLData.NextUpdate) {
                $dtNextUpdate = (
                    [datetime]$oCRLData.NextUpdate
                ).ToUniversalTime()
            }

            $iDaysRemaining = $null
            $dTotalDaysRemaining = $null
            $dValidityHours = $null
            $dPublicationMarginHours = $null
            $dPublicationMarginElapsedPercent = $null
            $bPublicationWindowUsable = $false

            if ($null -ne $dtNextUpdate) {
                $dTotalDaysRemaining = (
                    $dtNextUpdate - $dtNowUtc
                ).TotalDays

                $iDaysRemaining = [int][System.Math]::Floor(
                    $dTotalDaysRemaining
                )

                $dValidityHours = (
                    $dtNextUpdate - $dtThisUpdate
                ).TotalHours
            }

            if (
                $null -ne $dtNextPublish -and
                $null -ne $dtNextUpdate -and
                $dtNextPublish -gt $dtThisUpdate -and
                $dtNextPublish -lt $dtNextUpdate
            ) {
                $bPublicationWindowUsable = $true

                $dPublicationMarginHours = (
                    $dtNextUpdate - $dtNextPublish
                ).TotalHours

                $dPublicationMarginElapsedPercent =
                    [System.Math]::Max(
                        0.0,
                        (
                            100.0 *
                            ($dtNowUtc - $dtNextPublish).TotalSeconds /
                            ($dtNextUpdate - $dtNextPublish).TotalSeconds
                        )
                    )
            }

            # --------------------------------------------------------
            # 5. Enrich and return the shared result.
            # --------------------------------------------------------

            $hAdditionalProperties = @{
                URL                             = $URL
                ThisUpdate                      = $dtThisUpdate
                NextUpdate                      = $dtNextUpdate
                NextPublish                     = $dtNextPublish
                DaysRemaining                   = $iDaysRemaining
                TotalDaysRemaining              = $dTotalDaysRemaining
                ValidityHours                   = $dValidityHours
                PublicationWindowUsable         = $bPublicationWindowUsable
                PublicationMarginHours          = $dPublicationMarginHours
                PublicationMarginElapsedPercent = $dPublicationMarginElapsedPercent
            }

            $oCRLData |
                Add-Member `
                    -NotePropertyMembers $hAdditionalProperties `
                    -Force `
                    -ErrorAction Stop

            $oCRLData
        }
    }
}