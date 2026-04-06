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

    .OUTPUTS
        [PSCustomObject[]] Certificate records with RequestID, CommonName,
        CertificateTemplate, NotBefore, NotAfter, SerialNumber, RequesterName,
        CertificateHash, SubmittedWhen.

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

        [string]$Template
    )

    $hSplitParams = Split-RemoteAndNativeParameters
    $hSplitParamsRemote = $hSplitParams.Remote

    return Invoke-Command @hSplitParamsRemote -ScriptBlock {
        param($CAName, $MaxResults, $Template)

        $sConfig = "$env:COMPUTERNAME\$CAName"

        $oView = New-Object -ComObject CertificateAuthority.View
        try {
            $oView.OpenConnection($sConfig)

            # Restrict to issued certificates (Disposition = 20)
            $iDispCol = $oView.GetColumnIndex($false, "Disposition")
            $oView.SetRestriction($iDispCol, 1, 0, 20)  # CVR_SEEK_EQ = 1

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
            )

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
                            $hCert[$sKey] = $oColEnum.GetValue(0)
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
    } -ArgumentList $hSplitParams.Native.CAName, $hSplitParams.Native.MaxResults, $hSplitParams.Native.Template
}
