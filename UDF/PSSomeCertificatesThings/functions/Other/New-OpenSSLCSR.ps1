function New-OpenSSLCSR {
    <#
    .SYNOPSIS
        Creates a new Certificate Signing Request using OpenSSL

    .DESCRIPTION
        Generates a Certificate Signing Request and private key using OpenSSL.
        Supports custom subject DN, SAN (DNS and IP), key length, password-protected keys,
        and certificate templates. Creates an OpenSSL configuration file and invokes openssl req.

    .PARAMETER Subject
        Complete subject distinguished name (e.g., "CN=example.com,OU=IT,O=Company,L=City,ST=State,C=US").
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
        State/Province (ST) component of the subject.

    .PARAMETER CountryCode
        Country Code (C) component of the subject (2-letter ISO code).

    .PARAMETER SANdns
        Array of DNS names to include in Subject Alternative Name extension.

    .PARAMETER SANipaddress
        Array of IP addresses to include in Subject Alternative Name extension.

    .PARAMETER KeyLength
        RSA key length in bits. Default: 2048.

    .PARAMETER CertificateTemplate
        Name of the certificate template to use (for Enterprise CA).

    .PARAMETER SettingsInfPath
        Path where the temporary OpenSSL configuration file will be created. Default: temp folder with timestamp.

    .PARAMETER KeyPassword
        SecureString password to protect the private key.

    .PARAMETER KeyOutPath
        Output path for the private key file. Default: temp folder with timestamp.

    .PARAMETER CSROutPath
        Output path for the CSR file. Default: temp folder with timestamp.

    .PARAMETER DoNotRemoveSettingsFile
        If specified, the temporary configuration file will not be deleted after CSR creation.

    .PARAMETER OpenSSLPath
        Path to OpenSSL executable or directory containing openssl.exe. If not specified, searches in PATH.

    .OUTPUTS
        None. Creates key and CSR files and displays their paths to console.

    .EXAMPLE
        New-OpenSSLCSR -CommonName "www.example.com" -Organisation "Company" -OrganisationalUnit "IT" -Locality "Paris" -State "IDF" -CountryCode "FR"

    .EXAMPLE
        $pwd = ConvertTo-SecureString "MyPassword123" -AsPlainText -Force
        New-OpenSSLCSR -Subject "CN=server.example.com,OU=IT,O=Company,C=US" -SANdns @("server.example.com", "www.example.com") -KeyPassword $pwd

    .EXAMPLE
        New-OpenSSLCSR -CommonName "api.example.com" -SANdns @("api.example.com", "api2.example.com") -SANipaddress @("192.168.1.10") -KeyLength 4096 -OpenSSLPath "C:\OpenSSL\bin"

    .NOTES
        Author  : Loïc Ade
        Version : 1.1
        Version History:
        - 1.1: Changed attribute from S= to ST=
    #>
    Param(
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
        [Alias("ST")]
        [string]$State,

        [Parameter(ParameterSetName = "CN")]
        [Alias("C", "Country")]
        [string]$CountryCode,

        [Alias("DNS")]
        [string[]]$SANdns,

        [Alias("IP")]
        [string[]]$SANipaddress,

        [int]$KeyLength = 2048,

        [Alias("Template")]
        [string]$CertificateTemplate,

        [string]$SettingsInfPath = ($env:TEMP + "\" + (Get-Date -Format "yyyyMMdd_HHmmss") + "_settings.inf"),

        [securestring]$KeyPassword,

        [string]$KeyOutPath = ($env:TEMP + "\" + (Get-Date -Format "yyyyMMdd_HHmmss") + "_cert.key"),

        [string]$CSROutPath = ($env:TEMP + "\" + (Get-Date -Format "yyyyMMdd_HHmmss") + "_cert.req"),

        [switch]$DoNotRemoveSettingsFile,

        [string]$OpenSSLPath
    )

    function Get-OpenSSLPath {
        Param(
            [string]$Inputpath
        )
        if ($Inputpath) {
            if (Test-Path $InputPath -PathType Leaf) {
                return $Inputpath
            } elseif (Test-Path ($Inputpath + "\openssl.exe")) {
                return $Inputpath + "\openssl.exe"
            } else {
                return ""
            }
        } else {
            try {
                return (Get-Command openssl).Source
            } catch {
                return "" 
            }
        }
    }

    function Convert-DNToOpenSSLConfig {
        Param(
            [Parameter(Position = 0, Mandatory)]
            [string]$DN
        )
        $_aDN = $DN.Split(",")
        [array]::Reverse($_aDN)
        $i = 1
        $_aResult = @()
        foreach($item in $_aDN) {
            if ($item -match "^([a-zA-Z]+)=(.+)$") {
                $_aResult += ($i.ToString() + "." + $Matches.1 + " = " + $Matches.2)
                $i += 1
            }
        }
        return ($_aResult -join "`n")
    }

    # Find OpenSSL
    $openSSL = Get-OpenSSLPath $OpenSSLPath
    #Write-Host "openSSLPath = $OpenSSLPath"
    #Write-Host "openSSL = $openSSL"

    # Build config file

    $sConfig = if ($CertificateTemplate) {
        @"
oid_section        = OIDs
[ OIDs ]

# This uses the short name of the template:
certificateTemplateName = 1.3.6.1.4.1.311.20.2

# Use this instead if you need to refer to the template by OID:
# certificateTemplateOID = 1.3.6.1.4.1.311.21.7
        
"@
    } else { 
        ""
    }

    $sConfig += @"
[ req ]
prompt             = no
string_mask        = default

# The size of the keys in bits:
default_bits       = $KeyLength
distinguished_name = req_dn
req_extensions     = req_ext

[ req_dn ]

# Note that the following are in 'reverse order' to what you'd expect to see in
# Windows and the numbering is irrelevant as long as each line's number differs.

# Domain Components style:
# Server name:
# 2.DC = com
# 1.DC = example
# commonName = Acme Web Server

# Locality style:
# countryName = GB
# stateOrProvinceName = London
# localityName = Letsby Avenue
# organizationName = Acme
# organizationalUnitName = IT Dept
# organizationalUnitName = Web Services
# commonName = Acme Web Server

"@

    $sConfig += if ($PSCmdlet.ParameterSetName -eq "CN") {
        $aSubject = @() + $(if ($CommonName) { "CN=$CommonName" } else { @() }) + `
                            $(if ($OrganisationalUnit) { "OU=$OrganisationalUnit" } else { @() }) + `
                            $(if ($Organisation) { "O=$Organisation" } else { @() }) + `
                            $(if ($Locality) { "L=$Locality" } else { @() }) + `
                            $(if ($State) { "ST=$State" } else { @() }) + `
                            $(if ($CountryCode) { "C=$CountryCode" } else { @() })
        $aSubject -Join "`n"
    } else {
        Convert-DNToOpenSSLConfig $Subject
    }


    $sConfig += if ($CertificateTemplate) {
@"


[ req_ext ]

#basicConstraints=critical,CA:TRUE

# This requests a certificate using the '$CertificateTemplate' template.  Check with the CA for the correct name to use,
# or alternatively comment it out and let the CA apply it:
# old line : certificateTemplateName = ASN1:PRINTABLESTRING:`$CertificateTemplate
certificateTemplateName = ASN1:UTF8STRING:$CertificateTemplate
"@
    } else {
@"


[ req_ext ]

#basicConstraints=critical,CA:TRUE

# This requests a certificate using the 'CertificateTemplate' template.  Check with the CA for the correct name to use,
# or alternatively comment it out and let the CA apply it:
# certificateTemplateName = ASN1:PRINTABLESTRING:CertificateTemplate
"@
    }

    $sConfig += if ($SANdns -or $SANipaddress) {
        $sConfigNewItem = @"


subjectAltName = @alt_names

[alt_names]
# To copy the CN (in the case of a DNS name in the CN) use:
# DNS = `${req_dn::commonName}

"@
        if ($SANdns) {
            $iSANDNS = 1
            foreach ($sDNSItem in $SANdns) {
                $sConfigNewItem += ("DNS.$iSANDNS = " + $sDNSItem + "`n")
                $iSANDNS += 1
            }
        }
        if ($SANipaddress) {
            $iSANIP = 1
            foreach ($sIPItem in $SANipaddress) {
                $sConfigNewItem += ("IP.$iSANIP = " + $sIPItem + "`n")
                $iSANIP += 1
            }
        }
        $sConfigNewItem
    } else {
        ""
    }
    
    # write config file
    $sConfig | Out-File -FilePath $SettingsInfPath -Encoding utf8

    # call openssl
    if ($KeyPassword) {
        $sPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($KeyPassword))
        #$sPass = $sPass.Replace("""", """""")
        Write-Verbose ("$openssl req -new -newkey rsa:$KeyLength -passout pass:$sPass -keyout ""$KeyOutPath"" -out ""$CSROutPath"" -config ""$SettingsInfPath""")
        $aArguments = @("req", "-new", "-newkey", "rsa:$KeyLength", "-passout", "pass:$sPass", "-keyout", $KeyOutPath, "-out", $CSROutPath, "-config", $SettingsInfPath)
        &$openssl $aArguments #req -new -newkey rsa:$KeyLength -passout pass:$sPass -keyout ""$KeyOutPath"" -out ""$CSROutPath"" -config ""$SettingsInfPath""
    } else {
        Write-Warning "Output private key not encrypted. Please use -KeyPassword to protect private key by a password."
        Write-Verbose ("$openssl req -new -newkey rsa:$KeyLength -nodes -keyout ""$KeyOutPath"" -out ""$CSROutPath"" -config ""$SettingsInfPath""")
        $aArguments = @("req", "-new", "-newkey", "rsa:$KeyLength", "-nodes", "-keyout", $KeyOutPath, "-out", $CSROutPath, "-config", $SettingsInfPath)
        &$openssl $aArguments #req -new -newkey rsa:$KeyLength -nodes -keyout ""$KeyOutPath"" -out ""$CSROutPath"" -config ""$SettingsInfPath""
    }
    
    if (Test-Path $KeyOutPath) {
        Write-Host "New Key: $KeyOutPath"
    }
    if (Test-Path $CSROutPath) {
        Write-Host "New CSR: $CSROutPath"
    }
    if ($DoNotRemoveSettingsFile.IsPresent) {
        Write-Host "OpenSSL config file: $SettingsInfPath"
    } else {
        Remove-Item $SettingsInfPath
    }
}
