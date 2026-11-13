# Certificate_Management

<div>
  <img src="icon.png" alt="icon" width="128" align="left" style="margin-right: 16px;" />

  A PowerShell CLI tool for managing X.509 certificates: CSR generation with OpenSSL, submission to a Windows PKI (ADCS), certificate retrieval and PFX creation, certificate viewing (files, HTTPS and SQL Server endpoints), and certificate renewal on RDS and SQL Server servers. Features an interactive wizard with back navigation for a guided experience.

  ![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
  ![Windows](https://img.shields.io/badge/Windows-10%2F11-0078D6)
  ![License](https://img.shields.io/badge/License-PolyForm%20Noncommercial-lightgrey)
</div>
<br clear="left" />

## Features

- **Guided Wizard**: Step-by-step certificate creation with back navigation at every step
- **CSR Generation**: Create Certificate Signing Requests via OpenSSL with DN or item-by-item input
- **Subject Alternative Names**: Interactive SAN input with DNS and IP validation, CN inclusion check
- **PKI Integration**: Submit CSR, issue and retrieve certificates from a Windows ADCS via ICertRequest COM
- **PFX Creation**: Merge certificate chain and private key into a PFX with OpenSSL
- **Advanced Mode**: Individual access to each step (CSR, submit, issue, retrieve, PFX)
- **Sign a Provided CSR**: Review a CSR sent by someone else, choose CA and template, get the signed certificate and chain (no PFX: the private key stays with the requester)
- **Export / Convert**: Convert a PFX to PFX, PEM (combined or separate) or DER; an unencrypted private key always ends up in a password-protected ZIP
- **Certificate Viewer**: Inspect a certificate from a file (PEM, DER, P7B, PFX), an HTTPS URL, a host or a SQL Server instance, with chain check, then create a new certificate from it
- **RDS Certificate Deployment**: Push a PFX to a Remote Desktop Services server (Connection Broker roles or standalone RDP listener)
- **SQL Server Certificate Renewal**: Renew the TLS certificate of a SQL Server instance, prepared without interruption, restart now or later
- **Expiring Certificates**: Browse certificates approaching expiration, start a prefilled PKI request, or export the list to an Excel-friendly CSV
- **NetScaler Certificate Checks**: Discover SSL virtual servers through the Nitro API and inspect certificates presented by candidate endpoints
- **Configurable**: CA/template selection filters plus independent report template include/exclude filters and expiry window

## Requirements

- Windows 10/11
- PowerShell 5.1 or later
- OpenSSL (included in `tools/OpenSSL-Win64/`) and 7-Zip (included in `tools/7-Zip/`)
- Access to a Windows ADCS Certificate Authority
- Active Directory module (for CA and template discovery)
- For RDS and SQL Server renewal: WinRM access and administrator rights on the target server

## Quick Start

```powershell
.\Certificate_Management.ps1
```

The main menu offers:
1. **Create CSR, Sign with PKI and create PFX** - Full guided workflow (item-by-item, full DN, or imported from an existing certificate)
2. **Sign a provided CSR** - Sign a CSR received from someone else
3. **Advanced certificate generation** - Individual steps for partial workflows
4. **View a certificate** - Display the details of a certificate
5. **Export / Convert certificate** - Convert a PFX to other formats
6. **Change the certificate of an application server** - **RDS server** or **SQL Server**
7. **Certificates expiring soon** - Set report parameters, then select a certificate to view its details and CA request metadata before choosing renewal, CSR-only generation, Windows viewer or OpenSSL. Export the list as CSV; returning from a detail view reuses the loaded report without querying the PKI again.
8. **Settings** - Configure selection and report filters

NetScaler checks are available under **Change the certificate of an application server**. They require the ADC HTTPS management URL and a read-only Nitro API credential; the script discovers candidate SSL vServers, SNI bindings and explicit Content Switching host rules.

The expiry report uses `ReportTemplateFilter`, `ReportTemplateExcludeFilter` and `ReportDaysAhead` in `input/config.json`. Empty inclusion filter means all templates; excluded templates are removed from both history-window calculation and results. The CSV uses semicolon delimiters for Excel in French regional settings.

## Certificate Viewer

1. **Source** - Choose a working folder, then one of its certificate files (opened directly when the folder holds only one), or **Other source** to enter:
   - a file path or an HTTPS URL
   - `host[:port]` (port 443 by default): HTTPS and SQL Server are tried at the same time, the first answer wins
   - `server\instance` (the port is asked to the SQL Server Browser) or `server,port`: SQL Server

   For a server, the certificate it presents to its clients is shown (no login needed). Every list offers **Back** and **Exit**
   - Supported files: PEM (bundles included), DER/CER/CRT, P7B, PFX/P12 (the password is asked when needed)
   - When the source holds several certificates, choose the one to view (listed from the leaf to the root)
2. **Details** - Subject, SAN (one per line, grouped by type), issuer, serial number, validity (days left), SHA1 / SHA256 fingerprints, public key, signature algorithm, key usages, basic constraints, template, SKI / AKI, CDP / AIA / OCSP URLs, private key presence
3. **Chain check** - The chain is built on this computer (revocation checked online) and each problem is shown
4. **Actions** - Create a new certificate or only a CSR from it (subject and SAN pre-filled), copy the DNS / IP SAN to the clipboard, open it in the Windows certificate viewer, or show the full OpenSSL decoding

## RDS Certificate Deployment

1. **Server** - Enter the RDS server (in a broker deployment, enter the Connection Broker)
2. **Connection** - A PSSession is opened with the provided credentials
3. **Current state** - The deployment mode is detected and the certificates in use are displayed
4. **Certificate source** - Choose one of:
   - **Renew with the same parameters**: subject and SAN of the current certificate; CA and template reused from the last request made for that CN in the working folders (asked if none). Only the private key password is asked.
   - **Generate a new certificate**: the usual PKI wizard, pre-filled from the current certificate
   - **Use an existing PFX**: from the working folders or any path (its password is asked)
5. **Checks** - Expiration and server name vs SAN are verified (warnings only)
6. **Roles** - Broker mode only: choose RD Gateway, RD Web Access, RD Publishing and/or RD Redirector
7. **Deployment** - After confirmation, the certificate is applied and the new state is displayed

In broker mode, the tool calls the `RDManagement` commands through the broker's `Microsoft.Windows.ServerManagerWorkflows` endpoint (the one Server Manager uses), opened directly from your workstation. Unlike `Get-RDCertificate` / `Set-RDCertificate` run in a remote session, this needs no CredSSP or delegation.

In standalone mode (no Connection Broker), the certificate is imported in `LocalMachine\My`, NETWORK SERVICE gets read access to the private key, and the certificate is bound to the `RDP-tcp` listener.

## SQL Server Certificate Renewal

1. **Server** - Enter the SQL Server computer; a PSSession is opened (administrator rights)
2. **Instances** - The instances are detected, with the configured certificate and the one presented on the network (a difference means a restart is pending); choose the instance to update
3. **Certificate source** - Same choices as for RDS: renew with the same parameters, generate a new certificate, or use an existing PFX
4. **Checks** - Expiration, chain, server name in the SAN, Server Authentication usage (warnings only)
5. **Preparation, without interruption** - Import in `LocalMachine\My`, read access to the private key for the service account (without it the instance cannot start), thumbprint written in the instance configuration
6. **Restart** - Now (connections are cut, then the certificate presented is checked) or later (the new certificate is used at the next restart of the service)

The encryption settings (ForceEncryption...) are never changed: only the certificate is renewed. SQL Server reads its certificate at startup, so a restart of the instance is always needed for the new certificate to be used.

## Workflow

1. **Certificate Object** - Enter the Distinguished Name (item-by-item or full DN format)
2. **Subject Alternative Names** - Add DNS names and IP addresses
3. **Certificate Authority** - Select from discovered ADCS CAs
4. **Certificate Template** - Select from published templates
5. **Private Key Password** - Set an optional password for the private key
6. **File Names** - Choose a friendly name for output files
7. **Submit, Issue, Retrieve** - Automated PKI interaction via ICertRequest
8. **PFX Generation** - Merge into a PKCS#12 file

## Project Structure

```
Certificate_Management/
├── Certificate_Management.ps1    # Main script
├── input/                        # Configuration files
│   └── config.json               # CA and template filters
├── tools/
│   ├── 7-Zip/                    # 7-Zip binaries (password-protected exports)
│   └── OpenSSL-Win64/            # OpenSSL binaries
├── working/                      # Generated certificates
├── UDF/                          # PowerShell modules
│   ├── PSSomeActiveDirectoryThings/
│   ├── PSSomeAuthThings/
│   ├── PSSomeCertificatesThings/ # OpenSSL, CSR, PKI functions
│   ├── PSSomeCLIThings/          # CLI dialog framework
│   ├── PSSomeCoreThings/         # Core utilities
│   ├── PSSomeDataThings/         # Data validation, regex
│   ├── PSSomeFileThings/         # 7-Zip archives, safe file names
│   ├── PSSomeMSSqlThings/        # SQL Server instances, certificate read and renewal
│   ├── PSSomeNetworkThings/      # Network utilities
│   └── PSSomeRDSThings/          # RDS certificate read / deployment
├── LICENSE
└── README.md
```

## Configuration

The `input/config.json` file allows filtering CA and template lists using regex patterns:

```json
{
    "CAFilter": "MyCA",
    "TemplateFilter": "WebServer|CustomTemplate"
}
```

These filters can also be edited from the **Settings** menu.

## Release Notes

### 2.8
- Added an expiring-certificate report with template inclusion/exclusion, template-validity-bounded history lookup, renewal deduplication by CN/SAN, a prefilled PKI request workflow and Excel-friendly CSV export
- Added dynamic NetScaler ADC SSL endpoint discovery through a dedicated read-only Nitro module, under the application server certificate menu

### 2.7
- Added "View a certificate": choose a working folder then a certificate file, or enter a file path (PEM, DER, P7B, PFX), an HTTPS URL, a `host[:port]` or a SQL Server instance (`server\instance`, `server,port`). For a `host[:port]`, HTTPS and SQL Server are tried at the same time and the first answer wins. Shows the details (SAN one per line), the chain check, then lets you create a new certificate or a CSR from it, copy its DNS / IP SAN, open it in the Windows certificate viewer or decode it with OpenSSL
- Added "SQL Server" certificate renewal: instance detection, certificate prepared without interruption (import, private key access for the service account, instance configuration), restart now or later, check of the certificate presented after the restart. Encryption settings are never changed
- "Change the certificate of an RDS server" moved into a new "Change the certificate of an application server" sub-menu, next to SQL Server
- "Import from existing certificate" now also accepts a PFX, a P7B or a PEM bundle (the leaf certificate is used)
- Every list of the new menus offers Back and Exit
- Fixed: a `host:port` was refused, and the certificate name was not extracted from `<name>_<date>` working folders
- New `PSSomeMSSqlThings` module

### 2.6
- Added "Change the certificate of an RDS server": shows the current certificates, deploys a PFX on a Connection Broker (role selection) or on a standalone Session Host (RDP listener). The certificate can be renewed with the same parameters, regenerated with the PKI, or taken from an existing PFX.

### 2.5
- Added "Sign a provided CSR": review the CSR, choose the CA and the template, get the signed certificate and chain in a working folder named after the CN (no PFX)
- Added "Export / Convert certificate": PFX to PFX (with or without password), PEM combined, PEM separate or DER; an unencrypted private key is stored in a password-protected ZIP (AES-256 or ZipCrypto)

### 2.4
- Added "Import from existing certificate" under Advanced > New Certificate Request to generate a CSR only from an existing certificate

### 2.3
- First public version
- Added "Import from existing certificate" entry to pre-fill a new request from a file path, an HTTPS URL or a host[:port]
- Improved PFX creation: cert files are requested if not already present in the working folder, and missing intermediates / root are pulled from the Windows certificate stores (user and computer)

### 2.2
- UI now allows going back almost everywhere

### 2.1
- Improved DN form UI
- Replaced Read-YesNoAnswer with Invoke-YesNoCLIDialog
- Reworked the main menu

### 2.0
- CN verification against SAN
- "All in one" option (the previous menu items moved under "Advanced")
- PKI work folder is no longer hardcoded

### 1.1.1
- Replaced Get-Credential with Read-Credential to work around a bug

### 1.1
- Certificate object form can now be repeated to validate the entered values
- Option to skip the template name
- Fixed the State field (it was impossible to fill)
- Fixed the form to allow CN with stars and French accented letters in other fields

### 1.0
- Initial release

## Disclaimer

This project is not affiliated with, endorsed by, or associated with Microsoft. Active Directory Certificate Services (ADCS) is a component of Windows Server. This tool is an independent project developed to simplify certificate management workflows.

## Author

**Loic Ade**

## License

This project is licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/). See the [LICENSE](LICENSE) file for details.
