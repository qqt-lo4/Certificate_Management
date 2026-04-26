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
- **Configurable**: CA and template name filters saved in a JSON config file

## Requirements

- Windows 10/11
- PowerShell 5.1 or later
- OpenSSL (included in `tools/OpenSSL-Win64/`)
- Access to a Windows ADCS Certificate Authority
- Active Directory module (for CA and template discovery)

## Quick Start

```powershell
.\Certificate_Management.ps1
```

The main menu offers:
1. **Create CSR, Sign with PKI and create PFX** - Full guided workflow (item-by-item or full DN)
2. **Advanced** - Individual steps for partial workflows
3. **Settings** - Configure CA and template name filters

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
│   └── PSSomeNetworkThings/      # Network utilities
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
