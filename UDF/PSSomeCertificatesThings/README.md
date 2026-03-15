# PSSomeCertificatesThings

A PowerShell module for certificate management utilities: PKI and CA operations, CSR creation and signing, CRL retrieval, and OpenSSL helpers.

## Features

### Other (13 functions)

| Function | Description |
|----------|-------------|
| `New-CSR` | Creates a new Certificate Signing Request using Windows certreq |
| `Sign-CSR` | Signs a CSR by resubmitting a pending request to a CA |
| `Get-IssuedCertificate` | Retrieves an issued certificate and chain from a CA |
| `Convert-P7BToCer` | Converts a PKCS#7 (.p7b) certificate bundle to CER format using OpenSSL |
| `Get-CSRInfo` | Parses a CSR file and extracts detailed information (subject, SAN, template, algorithms) |
| `Write-CSRInfoToHost` | Displays CSR information to the console in a formatted manner |
| `Send-CSRToCA` | Submits a CSR to a Certificate Authority using certreq |
| `ConvertTo-Certificate` | Converts various certificate representations to X509Certificate2 object |
| `Get-IssuerCertificate` | Retrieves the issuer certificate from a certificate chain |
| `ConvertTo-DERString` | Converts byte arrays to DER (Distinguished Encoding Rules) string format |
| `Get-CertificateURL` | Extracts CDP, AIA, and OCSP URLs from a certificate using cryptnet.dll |
| `Get-CRL` | Downloads and parses a Certificate Revocation List from a URL |
| `New-OpenSSLCSR` | Creates a CSR and private key using OpenSSL (v1.1) |
| `Merge-OpenSSLPFX` | Merges a private key, certificate, and chain into a PFX file using OpenSSL |
| `Get-CertificateTemplate` | Extracts certificate template information from an X509Certificate2 object |

### PKI (7 functions)

| Function | Description |
|----------|-------------|
| `Get-PublicKeyServices` | Retrieves the Public Key Services container from Active Directory |
| `Get-CertificateTemplates` | Retrieves all certificate templates from Active Directory |
| `Get-CA` | Retrieves Certificate Authorities from the AIA container in Active Directory |
| `Get-CAEnrollmentServices` | Retrieves CA Enrollment Services from Active Directory |
| `Get-PublishedCertificateTemplates` | Retrieves certificate templates published on a specific CA |
| `Get-ADCA` | Retrieves comprehensive CA information including enrollment services and templates |

## Requirements

- **PowerShell** 5.1 or later
- **Windows** operating system
- **Active Directory** domain (for PKI functions)
- **OpenSSL** (optional, for OpenSSL-related functions)
- **certreq.exe** (for Windows CSR/certificate operations)
- **Administrator privileges** (for some operations)

## Installation

```powershell
# Clone or copy the module to a PowerShell module path
Copy-Item -Path ".\PSSomeCertificatesThings" -Destination "$env:USERPROFILE\Documents\PowerShell\Modules\PSSomeCertificatesThings" -Recurse

# Or import directly
Import-Module ".\PSSomeCertificatesThings\PSSomeCertificatesThings.psd1"
```

## Quick Start

### Creating Certificate Signing Requests

```powershell
# Create a CSR using Windows certreq
New-CSR -CommonName "www.example.com" -Organisation "Company" -OrganisationalUnit "IT" -Locality "Paris" -State "IDF" -CountryCode "FR" -SANdns @("www.example.com", "example.com")

# Create a CSR using OpenSSL with password-protected key
$keyPwd = ConvertTo-SecureString "MyPassword123" -AsPlainText -Force
New-OpenSSLCSR -CommonName "api.example.com" -Organisation "Company" -KeyLength 4096 -KeyPassword $keyPwd

# Parse CSR information
$csrInfo = Get-CSRInfo -Path "C:\Certs\request.csr"
Write-CSRInfoToHost -CSRInfo $csrInfo
```

### Working with Certificate Authorities

```powershell
# Submit a CSR to a CA
$result = Send-CSRToCA -CSRPath "C:\Temp\cert.req" -PKIServer "PKI-Server" -CAName "CompanyCA" -TemplateName "WebServer"
if ($result.Success) {
    Write-Host "Request ID: $($result.RequestID)"
}

# Sign a pending request
Sign-CSR -RequestID "123" -CAName "CompanyCA"

# Retrieve the issued certificate
Get-IssuedCertificate -RequestID "123" -CAName "CompanyCA" -CertOut "C:\Certs\cert.cer" -CertChainOut "C:\Certs\chain.p7b" -PKIWorkFolder "C:\Temp"
```

### Certificate Conversion and Manipulation

```powershell
# Convert P7B to CER
Convert-P7BToCer -P7bPath "C:\Certs\chain.p7b" -OutCerFile "C:\Certs\certificates.cer"

# Merge certificate and key into PFX
$pfxPwd = ConvertTo-SecureString "PFXPassword" -AsPlainText -Force
Merge-OpenSSLPFX -Cert "cert.cer" -PrivateKey "key.key" -RootCA "root.cer" -PFXPassword $pfxPwd -WindowsPFX -FriendlyName "My Certificate"

# Get certificate URLs
$cert = Get-Item Cert:\LocalMachine\My\THUMBPRINT
$urls = Get-CertificateURL -Cert $cert
$urls.CDP  # Certificate Distribution Points
$urls.AIA  # Authority Information Access
$urls.OCSP # OCSP responder URLs
```

### PKI and Active Directory Operations

```powershell
# Get all certificate templates
$templates = Get-CertificateTemplates
$templates | Select-Object Name, displayName

# Get Certificate Authorities
$cas = Get-ADCA
$cas | ForEach-Object {
    Write-Host "$($_.Name) - $($_.dNSHostName)"
    $_.CertificateTemplates
}

# Get templates published on a specific CA
$publishedTemplates = Get-PublishedCertificateTemplates -CA "CompanyCA"

# Get enrollment services
$services = Get-CAEnrollmentServices -Server "ca-server.example.com"
```

### Certificate Information Extraction

```powershell
# Extract certificate template information
$cert = Get-Item Cert:\LocalMachine\My\THUMBPRINT
$template = Get-CertificateTemplate -Certificate $cert
Write-Host "Template: $($template.Name) (OID: $($template.OID))"
Write-Host "Version: $($template.MajorVersion).$($template.MinorVersion)"

# Get issuer certificate
$issuer = Get-IssuerCertificate -Cert $cert

# Download and parse a CRL
$crl = Get-CRL -URL "http://pki.company.com/crl/ca.crl" -DownloadTimeout 30
```

## CSR Creation Workflows

### Windows-based CSR Workflow

```powershell
# 1. Create CSR
New-CSR -CommonName "server.example.com" `
        -Organisation "Company Inc" `
        -OrganisationalUnit "IT Department" `
        -Locality "New York" `
        -State "NY" `
        -CountryCode "US" `
        -SANdns @("server.example.com", "www.example.com", "api.example.com") `
        -KeyLength 4096 `
        -OutPath "C:\Certs\request.csr"

# 2. View CSR information
Write-CSRInfoToHost -Path "C:\Certs\request.csr"

# 3. Submit to CA
$result = Send-CSRToCA -CSRPath "C:\Certs\request.csr" `
                        -PKIServer "PKI01" `
                        -CAName "CompanyCA" `
                        -TemplateName "WebServer"

# 4. If pending, approve it
if (-not $result.Success) {
    Sign-CSR -RequestID $result.RequestID -CAName "CompanyCA"
}

# 5. Retrieve the issued certificate
Get-IssuedCertificate -RequestID $result.RequestID `
                       -CAName "CompanyCA" `
                       -CertOut "C:\Certs\cert.cer" `
                       -CertChainOut "C:\Certs\chain.p7b" `
                       -PKIWorkFolder "C:\Temp"
```

### OpenSSL-based CSR Workflow

```powershell
# 1. Create CSR and private key with OpenSSL
$keyPassword = ConvertTo-SecureString "MySecurePassword123!" -AsPlainText -Force
New-OpenSSLCSR -CommonName "secure.example.com" `
               -Organisation "Company Inc" `
               -OrganisationalUnit "Security" `
               -Locality "London" `
               -State "England" `
               -CountryCode "GB" `
               -SANdns @("secure.example.com", "*.secure.example.com") `
               -KeyLength 4096 `
               -KeyPassword $keyPassword `
               -KeyOutPath "C:\Certs\private.key" `
               -CSROutPath "C:\Certs\request.csr" `
               -OpenSSLPath "C:\OpenSSL\bin"

# 2. Submit CSR to CA (using Windows CA)
$result = Send-CSRToCA -CSRPath "C:\Certs\request.csr" `
                        -PKIServer "PKI01" `
                        -CAName "CompanyCA"

# 3. After receiving the certificate, create PFX
$pfxPassword = ConvertTo-SecureString "PFXPassword123!" -AsPlainText -Force
Merge-OpenSSLPFX -Cert "C:\Certs\cert.cer" `
                 -PrivateKey "C:\Certs\private.key" `
                 -RootCA "C:\Certs\root-ca.cer" `
                 -IntermediateCA "C:\Certs\intermediate-ca.cer" `
                 -KeyPassword $keyPassword `
                 -PFXPassword $pfxPassword `
                 -WindowsPFX `
                 -FriendlyName "Secure Server Certificate" `
                 -OutPFXFile "C:\Certs\certificate.pfx"
```

## Active Directory PKI Management

### Auditing Certificate Templates

```powershell
# Get all templates and their details
$templates = Get-CertificateTemplates
$templates | Select-Object Name, displayName, @{N='Flags';E={$_.flags}} | Format-Table

# Find which CAs publish specific templates
$templateName = "WebServer"
$cas = Get-ADCA
foreach ($ca in $cas) {
    if ($ca.CertificateTemplates -contains $templateName) {
        Write-Host "$($ca.Name) publishes $templateName"
    }
}
```

### CA Inventory

```powershell
# Comprehensive CA inventory
$allCAs = Get-ADCA

foreach ($ca in $allCAs) {
    Write-Host "`n=== $($ca.Name) ===" -ForegroundColor Cyan
    Write-Host "Server: $($ca.dNSHostName)"
    Write-Host "Published Templates ($($ca.CertificateTemplates.Count)):"
    $ca.CertificateTemplates | ForEach-Object { Write-Host "  - $_" }
}
```

### Template Assignment Report

```powershell
# Create a report of templates and their publishing CAs
$templates = Get-CertificateTemplates
$cas = Get-ADCA

$report = foreach ($template in $templates) {
    $publishingCAs = $cas | Where-Object { $_.CertificateTemplates -contains $template.Name } | Select-Object -ExpandProperty Name
    [PSCustomObject]@{
        TemplateName = $template.Name
        DisplayName = $template.displayName
        PublishingCAs = ($publishingCAs -join ', ')
        CACount = $publishingCAs.Count
    }
}

$report | Sort-Object TemplateName | Format-Table -AutoSize
```

## Certificate Validation and Inspection

### Validate Certificate Chain

```powershell
# Load certificate
$cert = Get-Item Cert:\LocalMachine\My\THUMBPRINT

# Get issuer
$issuer = Get-IssuerCertificate -Cert $cert
Write-Host "Certificate: $($cert.Subject)"
Write-Host "Issued by: $($issuer.Subject)"

# Get URLs for validation
$urls = Get-CertificateURL -Cert $cert

# Download and check CRL
foreach ($crlUrl in $urls.CDP) {
    Write-Host "`nDownloading CRL from: $crlUrl"
    try {
        $crl = Get-CRL -URL $crlUrl -DownloadTimeout 15
        Write-Host "CRL Issuer: $($crl.Issuer)"
        Write-Host "Next Update: $($crl.NextUpdate)"
    } catch {
        Write-Warning "Failed to retrieve CRL: $_"
    }
}
```

### Extract and Display Certificate Information

```powershell
# Get certificate from store
$cert = Get-Item Cert:\CurrentUser\My\THUMBPRINT

# Extract template information
$template = Get-CertificateTemplate -Certificate $cert
if ($template) {
    Write-Host "Certificate Template Information:" -ForegroundColor Green
    Write-Host "  Name: $($template.Name)"
    Write-Host "  OID: $($template.OID)"
    Write-Host "  Version: $($template.MajorVersion).$($template.MinorVersion)"
}

# Get certificate URLs
$urls = Get-CertificateURL -Cert $cert
Write-Host "`nCertificate URLs:" -ForegroundColor Green
Write-Host "  CDP: $($urls.CDP -join ', ')"
Write-Host "  AIA: $($urls.AIA -join ', ')"
Write-Host "  OCSP: $($urls.OCSP -join ', ')"
```

## Remote CA Operations

```powershell
# Create a remote session to CA server
$session = New-PSSession -ComputerName "CA-Server"

# Submit CSR remotely
$result = Send-CSRToCA -Session $session `
                        -CSRPath "request.csr" `
                        -PKIServer "CA-Server" `
                        -CAName "CompanyCA"

# Sign the request remotely
Sign-CSR -Session $session -RequestID $result.RequestID -CAName "CompanyCA"

# Retrieve the certificate remotely
Get-IssuedCertificate -Session $session `
                       -RequestID $result.RequestID `
                       -CAName "CompanyCA" `
                       -CertOut "C:\Local\cert.cer" `
                       -CertChainOut "C:\Local\chain.p7b" `
                       -PKIWorkFolder "C:\Temp"

# Clean up
Remove-PSSession $session
```

## Module Structure

```
PSSomeCertificatesThings/
├── PSSomeCertificatesThings.psd1    # Module manifest
├── PSSomeCertificatesThings.psm1    # Module loader (dot-sources all .ps1 files)
├── README.md                         # This file
├── LICENSE                           # PolyForm Noncommercial License
├── Other/                            # Certificate and CSR utilities (13 functions)
│   ├── New-CSR.ps1
│   ├── Sign-CSR.ps1
│   ├── Get-IssuedCertificate.ps1
│   ├── Convert-P7BtoCer.ps1
│   ├── Get-CSRInfo.ps1
│   ├── Write-CSRInfoToHost.ps1
│   ├── Send-CSRToCA.ps1
│   ├── ConvertTo-Certificate.ps1
│   ├── Get-IssuerCertificate.ps1
│   ├── ConvertTo-DERString.ps1
│   ├── Get-CertificateURL.ps1
│   ├── Get-CRL.ps1
│   ├── New-OpenSSLCSR.ps1
│   ├── Merge-OpenSSLPFX.ps1
│   └── Get-CertificateTemplate.ps1
└── PKI/                              # Active Directory PKI functions (7 functions)
    ├── Get-PublicKeyServices.ps1
    ├── Get-CertificateTemplates.ps1
    ├── Get-CA.ps1
    ├── Get-CAEnrollmentServices.ps1
    ├── Get-PublishedCertificateTemplates.ps1
    ├── Get-ADCA.ps1
    └── Get-ADCA.ps1
```

## Common Use Cases

### Automating Certificate Requests

```powershell
# Automated certificate request and installation
function Request-ServerCertificate {
    param(
        [string]$ServerName,
        [string[]]$SANNames,
        [string]$CAName = "CompanyCA"
    )

    # Create CSR
    New-CSR -CommonName $ServerName `
            -Organisation "Company Inc" `
            -OrganisationalUnit "IT" `
            -Locality "City" `
            -State "State" `
            -CountryCode "US" `
            -SANdns $SANNames `
            -KeyLength 2048 `
            -OutPath "$env:TEMP\$ServerName.csr"

    # Submit to CA
    $result = Send-CSRToCA -CSRPath "$env:TEMP\$ServerName.csr" `
                            -PKIServer "PKI01" `
                            -CAName $CAName `
                            -TemplateName "WebServer"

    if ($result.Success) {
        Write-Host "Certificate issued successfully. Request ID: $($result.RequestID)"
    } else {
        # Sign if pending
        Sign-CSR -RequestID $result.RequestID -CAName $CAName
        Write-Host "Request signed. Request ID: $($result.RequestID)"
    }
}

# Usage
Request-ServerCertificate -ServerName "web01.example.com" `
                          -SANNames @("web01.example.com", "www.example.com")
```

### PKI Health Check

```powershell
# Check PKI health
function Test-PKIHealth {
    Write-Host "=== PKI Health Check ===" -ForegroundColor Cyan

    # Check CAs
    $cas = Get-ADCA
    Write-Host "`nCertificate Authorities: $($cas.Count)"
    foreach ($ca in $cas) {
        Write-Host "  $($ca.Name) on $($ca.dNSHostName)" -ForegroundColor Green
        Write-Host "    Templates: $($ca.CertificateTemplates.Count)"
    }

    # Check Templates
    $templates = Get-CertificateTemplates
    Write-Host "`nCertificate Templates: $($templates.Count)"

    # Check Enrollment Services
    $services = Get-CAEnrollmentServices
    Write-Host "`nEnrollment Services: $($services.Count)"
    foreach ($service in $services) {
        Write-Host "  $($service.Name) on $($service.dNSHostName)" -ForegroundColor Green
    }
}

Test-PKIHealth
```

### Batch Certificate Export

```powershell
# Export all certificates with their chains to PFX
Get-ChildItem Cert:\LocalMachine\My | ForEach-Object {
    $cert = $_
    $friendlyName = if ($cert.FriendlyName) { $cert.FriendlyName } else { $cert.Subject }
    $fileName = $cert.Thumbprint + ".pfx"

    Write-Host "Exporting: $friendlyName"

    # This would require the private key to be exportable
    # $password = ConvertTo-SecureString "ExportPassword" -AsPlainText -Force
    # Export-PfxCertificate -Cert $cert -FilePath $fileName -Password $password
}
```

## Security Notes

- **Administrator Privileges**: Many certificate operations (especially CSR creation with `New-CSR`) require administrator privileges
- **Private Key Protection**: Always use password protection for private keys (`KeyPassword` parameter in OpenSSL functions)
- **PFX Password Protection**: Use the `-PFXPassword` parameter when creating PFX files to protect the private key
- **Windows-Compatible PFX**: Use the `-WindowsPFX` switch when creating PFX files for Windows systems
- **Remote Sessions**: When using remote sessions, ensure proper authentication and encrypted channels
- **CRL Validation**: Always check CRLs and OCSP for certificate revocation status
- **Certificate Storage**: Store certificates and private keys in secure locations with appropriate ACLs

## Technical Details

### Supported Certificate Formats

- **CSR**: PKCS#10 format (`.csr`, `.req`)
- **Certificates**: X.509 (`.cer`, `.crt`)
- **Certificate Chains**: PKCS#7 (`.p7b`)
- **Private Keys**: PKCS#8, RSA PEM (`.key`, `.pem`)
- **PFX/PKCS#12**: `.pfx`, `.p12`

### Hash Algorithms

- SHA-256 (recommended)
- SHA-384
- SHA-512
- SHA-1 (legacy)
- MD5, MD4, MD2 (not recommended)

### Key Algorithms

- RSA (default)
- ECDSA (P-256, P-384, P-521)
- ECDH (P-256, P-521)
- DH, DSA (legacy)

### Certificate Extensions

- **Subject Alternative Name (SAN)**: DNS names and IP addresses
- **Key Usage**: Digital signature, key encipherment, etc.
- **Extended Key Usage**: Server authentication, client authentication, etc.
- **Certificate Template**: Microsoft template name and OID
- **CDP**: Certificate Distribution Points for CRL
- **AIA**: Authority Information Access for issuer certificate
- **OCSP**: Online Certificate Status Protocol responders

## Troubleshooting

### OpenSSL Not Found

```powershell
# Specify OpenSSL path explicitly
New-OpenSSLCSR -CommonName "test.com" -OpenSSLPath "C:\OpenSSL\bin\openssl.exe"
```

### Administrator Privileges Required

```powershell
# Check if running as administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "This operation requires administrator privileges"
}
```

### Certificate Template Not Found

```powershell
# List available templates on a CA
$templates = Get-PublishedCertificateTemplates -CA "CompanyCA"
$templates | Select-Object Name, displayName
```

## Author

**Loïc Ade**

## License

This project is licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/). See the [LICENSE](LICENSE) file for details.

In short:
- **Non-commercial use only** — You may use, modify, and distribute this software for any non-commercial purpose.
- **Attribution required** — You must include a copy of the license terms with any distribution.
- **No warranty** — The software is provided as-is.
