function New-CSR {
    <#
    .SYNOPSIS
        Creates a new Certificate Signing Request (CSR)

    .DESCRIPTION
        Generates a Certificate Signing Request using Windows certreq utility.
        Supports custom subject DN, SAN (DNS and IP), key algorithms, hash algorithms,
        and certificate templates. Creates an INF configuration file and invokes certreq.

    .PARAMETER FriendlyName
        Friendly name for the certificate.

    .PARAMETER Subject
        Complete subject distinguished name (e.g., "CN=example.com,OU=IT,O=Company,L=City,S=State,C=US").
        Used with the Subject parameter set.

    .PARAMETER CommonName
        Common Name (CN) component of the subject. Used with the CN parameter set.

    .PARAMETER Organisation
        Organization (O) component of the subject.

    .PARAMETER OrganisationalUnit
        Organizational Unit (OU) component of the subject.

    .PARAMETER Locality
        Locality/City (L) component of the subject.

    .PARAMETER State
        State/Province (S) component of the subject.

    .PARAMETER CountryCode
        Country Code (C) component of the subject (2-letter ISO code).

    .PARAMETER SANdns
        Array of DNS names to include in Subject Alternative Name extension.

    .PARAMETER SANipaddress
        Array of IP addresses to include in Subject Alternative Name extension.

    .PARAMETER KeyLength
        RSA key length in bits. Default: 2048.

    .PARAMETER Exportable
        Whether the private key should be exportable. Default: $true.

    .PARAMETER MachineKeySet
        Whether to use machine key storage. Default: $true.

    .PARAMETER SMIME
        Whether this is an S/MIME certificate. Default: $false.

    .PARAMETER RequestType
        Type of request to create. Default: "PKCS10".

    .PARAMETER ProviderName
        Cryptographic provider name. Default: "Microsoft RSA SChannel Cryptographic Provider".

    .PARAMETER ProviderType
        Cryptographic provider type. Default: 12.

    .PARAMETER HashAlgorithm
        Hash algorithm for signing. Valid values: sha256, sha384, sha512, sha1, md5, md4, md2. Default: sha256.

    .PARAMETER KeyAlgorithm
        Key algorithm. Valid values: RSA, DH, DSA, ECDH_P256, ECDH_P521, ECDSA_P256, ECDSA_P384, ECDSA_P521. Default: RSA.

    .PARAMETER CertificateTemplate
        Name of the certificate template to use (for Enterprise CA).

    .PARAMETER settingsInfPath
        Path where the temporary INF configuration file will be created. Default: temp folder with timestamp.

    .PARAMETER OutPath
        Output path for the CSR file. If not specified, CSR content is returned and temporary file is deleted.

    .PARAMETER DoNotRemoveSettingsFile
        If specified, the temporary INF configuration file will not be deleted after CSR creation.

    .OUTPUTS
        [String]. CSR content (if OutPath not specified) or file created at OutPath.

    .EXAMPLE
        New-CSR -CommonName "www.example.com" -Organisation "Company" -OrganisationalUnit "IT" -Locality "Paris" -State "IDF" -CountryCode "FR"

    .EXAMPLE
        New-CSR -Subject "CN=server.example.com,OU=IT,O=Company,C=US" -SANdns @("server.example.com", "www.example.com") -OutPath "C:\Temp\cert.req"

    .EXAMPLE
        New-CSR -CommonName "api.example.com" -SANdns @("api.example.com", "api2.example.com") -SANipaddress @("192.168.1.10") -KeyLength 4096

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [string]$FriendlyName,

        [Parameter(Mandatory, ParameterSetName = "Subject")]
        [string]$Subject,

        [Parameter(Mandatory, ParameterSetName = "CN")]
        [Alias("CN")]
        [string]$CommonName,

        [Parameter(ParameterSetName = "CN")]
        [Alias("O")]
        [string]$Organisation,

        [Parameter(ParameterSetName = "CN")]
        [Alias("OU")]
        [string]$OrganisationalUnit,

        [Parameter(ParameterSetName = "CN")]
        [Alias("L", "City")]
        [string]$Locality,

        [Parameter(ParameterSetName = "CN")]
        [Alias("S")]
        [string]$State,

        [Parameter(ParameterSetName = "CN")]
        [Alias("C", "Country")]
        [string]$CountryCode,

        [Alias("DNS")]
        [string[]]$SANdns,

        [Alias("IP")]
        [string[]]$SANipaddress,

        [int]$KeyLength = 2048,

        [bool]$Exportable = $true,

        [bool]$MachineKeySet = $true, 

        [bool]$SMIME = $false,

        [string]$RequestType = "PKCS10",

        [string]$ProviderName = "Microsoft RSA SChannel Cryptographic Provider",
    
        [int]$ProviderType =  12,

        [ValidateSet("sha256", "sha384", "sha512", "sha1", "md5", "md4", "md2")]
        [string]$HashAlgorithm = "sha256",

        [ValidateSet("RSA", "DH", "DSA", "ECDH_P256", "ECDH_P521", "ECDSA_P256", "ECDSA_P384", "ECDSA_P521")]
        [string]$KeyAlgorithm = "RSA",

        [Alias("Template")]
        [string]$CertificateTemplate,

        [string]$settingsInfPath = ($env:TEMP + "\" + (Get-Date -Format "yyyymmdd_HHmmss") + "_settings.inf"),

        [string]$OutPath,

        [switch]$DoNotRemoveSettingsFile
    )

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Host "Administrator priviliges are required. Please restart this script with elevated rights." -ForegroundColor Red
        Throw "Administrator priviliges are required. Please restart this script with elevated rights."
    }

    $sSubject = if ($PSCmdlet.ParameterSetName -eq "CN") {
        $aSubject = @() + $(if ($CommonName) { "CN=$CommonName" } else { @() }) + `
                            $(if ($OrganisationalUnit) { "OU=$OrganisationalUnit" } else { @() }) + `
                            $(if ($Organisation) { "O=$Organisation" } else { @() }) + `
                            $(if ($Locality) { "L=$Locality" } else { @() }) + `
                            $(if ($State) { "S=$State" } else { @() }) + `
                            $(if ($CountryCode) { "C=$CountryCode" } else { @() })
        $aSubject -Join ","
    } else {
        $Subject
    }

    $NewRequestSection = @"
[NewRequest]
KeyLength = $KeyLength
Exportable = $($Exportable.ToString())
MachineKeySet = $($MachineKeySet.ToString())
SMIME = $($SMIME.ToString())
RequestType = $RequestType
ProviderName = $("`"" + $ProviderName + "`"")
ProviderType = $ProviderType
HashAlgorithm = $HashAlgorithm
;Variables
Subject = $("`"" + $sSubject + "`"")
$(if ($FriendlyName) { "FriendlyName = `"$FriendlyName`"`n" })

"@

    $ExtensionsSection = if ($SANdns -or $SANipaddress) {
        $result = @"
[Extensions]
2.5.29.17 = "{text}"
"@
        foreach ($sDNS in $SANdns) {
            $result += "`n_continue_ = `"dns=" + $sDNS + "&`""
        }
        foreach ($sIP in $SANipaddress) {
            $result += "`n_continue_ = `"ipaddress=" + $sIP + "&`""
        }
        $result += "`n`n"
        $result
    } else {
        ""
    }

    $VersionSection = @"
[Version] 
Signature=`"`$Windows NT`$`"


"@

    $RequestAttributesSection = if ($CertificateTemplate) {
        @"
[RequestAttributes]
CertificateTemplate=$("`"" + $CertificateTemplate + "`"")


"@
    } else {
        ""
    }

    $settingsFileContent = $VersionSection + $NewRequestSection + $ExtensionsSection + $RequestAttributesSection
    
    $settingsFileContent | Out-File -FilePath $SettingsInfPath
    
    $sOutCSRPath = if ($OutPath) {
        $OutPath
    } else {
        $env:TEMP + "\" + (Get-Date -Format "yyyymmdd_HHmmss") + "_cert.req"
    }

    cmd /c "certreq -new $SettingsInfPath $sOutCSRPath"
    
    if (-not $DoNotRemoveSettingsFile.IsPresent) {
        Remove-Item $SettingsInfPath
    }
    
    if ((-not $OutPath) -and (Test-Path $sOutCSRPath)) {
        Get-Content $sOutCSRPath
        Remove-Item $sOutCSRPath
    }
}