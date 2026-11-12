function Get-CAIssuedCertificates {
    <#
    .SYNOPSIS
        Retrieves issued certificates from a Microsoft Certificate Authority.

    .DESCRIPTION
        Uses the ICertView2 COM interface to query the CA database for issued
        certificates. Returns certificate metadata sorted by most recent first.
        Supports remote execution via PSSession or ComputerName.

    .PARAMETER Session
        PSSession to execute the command remotely on the CA server.

    .PARAMETER ComputerName
        Name of the remote computer hosting the CA.

    .PARAMETER Credential
        Credentials for remote execution (used with ComputerName).

    .PARAMETER CAName
        Name of the Certificate Authority (without server prefix).

    .PARAMETER MaxResults
        Maximum number of certificates to return. Default: 100.

    .PARAMETER Template
        Filter by certificate template name. Optional.

    .PARAMETER IssuedOnFrom
        Return certificates resolved on or after this date. Optional.

    .PARAMETER IncludeSAN
        Decode the certificate SAN extension and return it as a hashtable.

    .PARAMETER IncludeRawCertificate
        Include the raw certificate bytes in the result.

    .OUTPUTS
        [PSCustomObject[]] Certificate records with RequestID, CommonName,
        CertificateTemplate, NotBefore, NotAfter, SerialNumber, RequesterName,
        CertificateHash, SubmittedWhen, ResolvedWhen, and optional SAN/RawCertificate.

    .EXAMPLE
        Get-CAIssuedCertificates -CAName "CompanyCA" -ComputerName "PKI01"

    .EXAMPLE
        Get-CAIssuedCertificates -CAName "CompanyCA" -Session $session -MaxResults 50

    .EXAMPLE
        $cred = Get-Credential
        Get-CAIssuedCertificates -CAName "CompanyCA" -ComputerName "PKI01" -Credential $cred -Template "WebServer"

    .NOTES
        Author  : Loic Ade
        Version : 1.1.0

        1.1.0 (2026-03-30) - Fixed ICertView2 column enumeration and sorting
        1.0.0 (2026-03-30) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ComputerName,
        [PSCredential]$Credential,

        [Parameter(Mandatory)]
        [string]$CAName,

        [int]$MaxResults = 100,

        [string]$Template,

        [datetime]$IssuedOnFrom,

        [switch]$IncludeSAN,

        [switch]$IncludeRawCertificate
    )

    $hSplitParams = Split-RemoteAndNativeParameters
    $hSplitParamsRemote = $hSplitParams.Remote

    $aCertificates = Invoke-Command @hSplitParamsRemote -ScriptBlock {
        param($CAName, $MaxResults, $Template, $IssuedOnFrom, $IncludeSAN, $IncludeRawCertificate)

        $sConfig = "$env:COMPUTERNAME\$CAName"

        $oView = New-Object -ComObject CertificateAuthority.View
        try {
            $oView.OpenConnection($sConfig)

            # Restrict to issued certificates (Disposition = 20)
            $iDispCol = $oView.GetColumnIndex($false, "Disposition")
            $oView.SetRestriction($iDispCol, 1, 0, 20)  # CVR_SEEK_EQ = 1
            if ($null -ne $IssuedOnFrom) {
                $iIssuedOnCol = $oView.GetColumnIndex($false, "Request.ResolvedWhen")
                $oView.SetRestriction($iIssuedOnCol, 16, 0, $IssuedOnFrom)  # CVR_SEEK_GE
            }

            # Define output columns
            $aColumnNames = @(
                "RequestID"
                "CommonName"
                "CertificateTemplate"
                "NotBefore"
                "NotAfter"
                "SerialNumber"
                "RequesterName"
                "CertificateHash"
                "Request.SubmittedWhen"
                "Request.ResolvedWhen"
            )
            if ($IncludeSAN -or $IncludeRawCertificate) { $aColumnNames += "RawCertificate" }

            $oView.SetResultColumnCount($aColumnNames.Count)
            foreach ($sCol in $aColumnNames) {
                $oView.SetResultColumn($oView.GetColumnIndex($false, $sCol))
            }

            $oRow = $oView.OpenView()
            $aResults = [System.Collections.ArrayList]::new()

            # Collect all matching rows (ICertView2 returns in ascending RequestID order)
            while ($oRow.Next() -ne -1) {
                $oColEnum = $oRow.EnumCertViewColumn()
                $hCert = [ordered]@{}

                foreach ($sCol in $aColumnNames) {
                    $sKey = $sCol -replace '^Request\.', ''
                    if ($oColEnum.Next() -ne -1) {
                        try {
                            $iOutputType = if ($sCol -eq "RawCertificate" -and $IncludeRawCertificate) { 1 } else { 0 }
                            $hCert[$sKey] = $oColEnum.GetValue($iOutputType)
                        } catch {
                            $hCert[$sKey] = $null
                        }
                    } else {
                        $hCert[$sKey] = $null
                    }
                }

                # Resolve template OID to display name
                if ($hCert['CertificateTemplate'] -and $hCert['CertificateTemplate'] -match '^\d+\.\d+') {
                    try {
                        $oOID = New-Object System.Security.Cryptography.Oid $hCert['CertificateTemplate']
                        if ($oOID.FriendlyName) {
                            $hCert['CertificateTemplate'] = $oOID.FriendlyName
                        }
                    } catch {}
                }

                # Apply template filter
                if ($Template -and $hCert['CertificateTemplate'] -notmatch [regex]::Escape($Template)) {
                    continue
                }

                [void]$aResults.Add([PSCustomObject]$hCert)
            }

            # Return last N results (most recent = highest RequestID = end of list)
            if ($aResults.Count -gt $MaxResults) {
                return @($aResults[($aResults.Count - $MaxResults)..($aResults.Count - 1)])
            }
            return $aResults.ToArray()
        } finally {
            try { [System.Runtime.InteropServices.Marshal]::ReleaseComObject($oView) | Out-Null } catch {}
        }
    } -ArgumentList $hSplitParams.Native.CAName, $hSplitParams.Native.MaxResults, $hSplitParams.Native.Template, `
        $hSplitParams.Native.IssuedOnFrom, $hSplitParams.Native.IncludeSAN, $hSplitParams.Native.IncludeRawCertificate

    if ($IncludeSAN) {
        foreach ($oCertificate in $aCertificates) {
            $hSAN = @{}
            try {
                $oRawCertificate = $oCertificate.RawCertificate
                if ($oRawCertificate -is [byte[]] -and $oRawCertificate.Length -gt 0 -and $oRawCertificate[0] -eq 0x30) {
                    $aRawCertificate = $oRawCertificate
                } else {
                    $sEncodedCertificate = if ($oRawCertificate -is [byte[]]) {
                        [System.Text.Encoding]::ASCII.GetString($oRawCertificate)
                    } else {
                        [string]$oRawCertificate
                    }
                    $sEncodedCertificate = $sEncodedCertificate -replace '-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s', ''
                    $aRawCertificate = [Convert]::FromBase64String($sEncodedCertificate)
                }
                if ($aRawCertificate.Length -gt 0) {
                    $oX509Certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,$aRawCertificate)
                    $hSAN = Get-CertificateSAN -Certificate $oX509Certificate
                }
            } catch {
                Write-Verbose "Could not decode SAN for request $($oCertificate.RequestID): $_"
            }
            $oCertificate | Add-Member -MemberType NoteProperty -Name SAN -Value $hSAN
            if (-not $IncludeRawCertificate) { $oCertificate.PSObject.Properties.Remove("RawCertificate") }
        }
    }
    return $aCertificates
}
