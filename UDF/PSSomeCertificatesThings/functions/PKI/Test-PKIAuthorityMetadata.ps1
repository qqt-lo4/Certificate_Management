function Test-PKIAuthorityMetadata {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [object]$Authority,

        [AllowEmptyCollection()]
        [object[]]$CertificateRecords = @()
    )

    $sCAName = [string]$Authority.Name
    $sHostName = [string]$Authority.dNSHostName

    $bHasSelfIssuedCertificate = @(
        $CertificateRecords |
            Where-Object {
                [System.Convert]::ToBase64String(
                    $_.Certificate.SubjectName.RawData
                ) -ceq
                [System.Convert]::ToBase64String(
                    $_.Certificate.IssuerName.RawData
                )
            }
    ).Count -gt 0

    if ($CertificateRecords.Count -eq 0) {
        New-PKIHealthFinding `
            -Status Critical `
            -Authority $sCAName `
            -Check 'CA certificate in AD' `
            -Details 'No matching CA certificate was found in AD.'
    }

    if ($sHostName) {
        try {
            Resolve-DnsName `
                -Name $sHostName `
                -ErrorAction Stop |
                Out-Null

            New-PKIHealthFinding `
                -Status Healthy `
                -Authority $sCAName `
                -Check 'DNS resolution' `
                -Details "$sHostName resolves."
        }
        catch {
            New-PKIHealthFinding `
                -Status Critical `
                -Authority $sCAName `
                -Check 'DNS resolution' `
                -Details (
                    "Could not resolve '$sHostName': " +
                    $_.Exception.Message
                )
        }
    }
    elseif ($bHasSelfIssuedCertificate) {
        New-PKIHealthFinding `
            -Status NotApplicable `
            -Authority $sCAName `
            -Check 'Enrollment Service hostname' `
            -Details (
                'No Enrollment Service hostname is available. ' +
                'This can be normal for an offline or standalone root.'
            )
    }
    else {
        New-PKIHealthFinding `
            -Status Unknown `
            -Authority $sCAName `
            -Check 'Enrollment Service hostname' `
            -Details (
                'No Enrollment Service hostname is available. ' +
                'The inventory alone cannot distinguish a standalone CA ' +
                'from incomplete AD publication.'
            )
    }

    $aTemplates = @(
        $Authority.CertificateTemplates |
            Where-Object { $_ }
    )

    if ($aTemplates.Count -gt 0) {
        New-PKIHealthFinding `
            -Status Healthy `
            -Authority $sCAName `
            -Check 'Published templates' `
            -Details "$($aTemplates.Count) template(s) published."
    }
    elseif (-not $sHostName) {
        New-PKIHealthFinding `
            -Status NotApplicable `
            -Authority $sCAName `
            -Check 'Published templates' `
            -Details (
                'No templates reported and no Enrollment Service ' +
                'hostname is available.'
            )
    }
    else {
        New-PKIHealthFinding `
            -Status Warning `
            -Authority $sCAName `
            -Check 'Published templates' `
            -Details 'No certificate templates are published on this CA.'
    }
}