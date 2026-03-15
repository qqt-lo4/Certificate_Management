function Get-CertificateTemplate {
    <#
    .SYNOPSIS
    Extracts certificate template information from an X509Certificate2 object.

    .DESCRIPTION
    Retrieves the certificate template name and information from certificate extensions.
    Uses CertEnroll COM components to decode the template extensions.

    .PARAMETER Certificate
    The X509Certificate2 object to analyze

    .OUTPUTS
    PSCustomObject with Name, OID, MajorVersion, MinorVersion properties

    .EXAMPLE
    Get-CertificateTemplate -Certificate $cert

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    process {
        try {
            # Microsoft certificate template extension OIDs
            $templateNameOID = "1.3.6.1.4.1.311.20.2"      # Certificate Template Name
            $templateInfoOID = "1.3.6.1.4.1.311.21.7"      # Certificate Template Information

            $hResult = [ordered]@{
                Name         = $null
                OID          = $null
                MajorVersion = $null
                MinorVersion = $null
            }

            # Certificate Template Name extension (friendly name via COM CertEnroll)
            $extName = $Certificate.Extensions[$templateNameOID]
            if ($extName) {
                $templateNameObj = New-Object -ComObject X509Enrollment.CX509ExtensionTemplateName
                $templateNameObj.InitializeDecode(1, [Convert]::ToBase64String($extName.RawData))
                $hResult.Name = $templateNameObj.TemplateName
                Write-Verbose "Template Name found via $templateNameOID : $templateName"
            }

            # Certificate Template Information extension (OID + versions via COM CertEnroll)
            $extInfo = $Certificate.Extensions[$templateInfoOID]
            if ($extInfo) {
                $templateExt = New-Object -ComObject X509Enrollment.CX509ExtensionTemplate
                $templateExt.InitializeDecode(1, [Convert]::ToBase64String($extInfo.RawData))
                $hResult.OID = $templateExt.TemplateOid.Value
                $hResult.MajorVersion = $templateExt.MajorVersion
                $hResult.MinorVersion = $templateExt.MinorVersion

                if (-not $hResult.Name -and $templateExt.TemplateOid.FriendlyName) {
                    $hResult.Name = $templateExt.TemplateOid.FriendlyName
                }

                Write-Verbose "Template Info (COM) : OID=$templateOID, Major=$majorVersion, Minor=$minorVersion"
            }

            return $hResult
        }
        catch {
            Write-Warning "Failed to extract certificate template: $($_.Exception.Message)"
            return $null
        }
    }
}
