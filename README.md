# Certificate_Management

<div>
  <img src="icon.png" alt="icon" width="128" align="left" style="margin-right: 16px;" />

  A PowerShell CLI tool for managing X.509 certificates: CSR generation with OpenSSL, submission to a Windows PKI (ADCS), certificate retrieval, and PFX creation. Features an interactive wizard with back navigation for a guided experience.

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
- **Certificate Viewer**: Inspect a certificate from a file (PEM, DER, P7B, PFX), an HTTPS URL or a host, with chain check
- **RDS Certificate Deployment**: Push a PFX to a Remote Desktop Services server (Connection Broker roles or standalone RDP listener)
- **Configurable**: CA and template name filters saved in a JSON config file

## Requirements

- Windows 10/11
- PowerShell 5.1 or later
- OpenSSL (included in `tools/OpenSSL-Win64/`)
- Access to a Windows ADCS Certificate Authority
- Active Directory module (for CA and template discovery)
- For RDS deployment: WinRM access and administrator rights on the target RDS server

## Quick Start

```powershell
.\Certificate_Management.ps1
```

The main menu offers:
1. **Create CSR, Sign with PKI and create PFX** - Full guided workflow (item-by-item or full DN)
2. **Advanced** - Individual steps for partial workflows
3. **View a certificate** - Display the details of a certificate
4. **Change the certificate of an application server** - **RDS server** or **SQL Server**
5. **Settings** - Configure CA and template name filters

## SQL Server Certificate Renewal

1. **Server** - Enter the SQL Server computer; a PSSession is opened (administrator rights)
2. **Instances** - The instances are detected, with the configured certificate and the one presented on the network (a difference means a restart is pending); choose the instance to update
3. **Certificate source** - Same choices as for RDS: renew with the same parameters, generate a new certificate, or use an existing PFX
4. **Checks** - Expiration, chain, server name in the SAN, Server Authentication usage (warnings only)
5. **Preparation, without interruption** - Import in `LocalMachine\My`, read access to the private key for the service account (without it the instance cannot start), thumbprint written in the instance configuration
6. **Restart** - Now (connections are cut, then the certificate presented is checked) or later (the new certificate is used at the next restart of the service)

The encryption settings (ForceEncryption...) are never changed: only the certificate is renewed.

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
│   └── OpenSSL-Win64/            # OpenSSL binaries
├── working/                      # Generated certificates
├── UDF/                          # PowerShell modules
│   ├── PSSomeActiveDirectoryThings/
│   ├── PSSomeAuthThings/
│   ├── PSSomeCertificatesThings/ # OpenSSL, CSR, PKI functions
│   ├── PSSomeCLIThings/          # CLI dialog framework
│   ├── PSSomeCoreThings/         # Core utilities
│   ├── PSSomeDataThings/         # Data validation, regex
│   ├── PSSomeMSSqlThings/        # SQL Server instances and certificate renewal
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

### 2.7
- Added "View a certificate": shows the details and the chain check of a certificate taken from the working folders, a file (PEM, DER, P7B, PFX), an HTTPS URL or a host; it can then be opened in the Windows certificate viewer or decoded with OpenSSL
- "Import from existing certificate" now also accepts a PFX, a P7B or a PEM bundle (the leaf certificate is used)

### 2.6
- Added "Change the certificate of an RDS server": shows the current certificates, deploys a PFX on a Connection Broker (role selection) or on a standalone Session Host (RDP listener). The certificate can be renewed with the same parameters, regenerated with the PKI, or taken from an existing PFX.

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
