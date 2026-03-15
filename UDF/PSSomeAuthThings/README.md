# PSSomeAuthThings

A PowerShell module for authentication and credential management: PSCredential helpers, password policy validation, password complexity testing, and Windows Credential Manager integration.

## Features

### Credential (6 functions)

| Function | Description |
|----------|-------------|
| `ConvertTo-PSCredential` | Converts a username and plain-text password to a PSCredential object |
| `Get-AuthenticationCredentials` | Retrieves credentials based on mode: userpasswd, passwdfile, or credential object |
| `New-PasswordPolicy` | Creates a password policy object with validation rules (length, complexity, forbidden patterns) |
| `Read-NewPassword` | Prompts for a new password with confirmation and optional policy validation |
| `Read-PasswordWithPolicy` | Prompts for a password while validating it against a policy |
| `Test-PasswordComplexity` | Tests a password against a complexity policy and returns missing requirements |

### CredManager (5 functions)

| Function | Description |
|----------|-------------|
| `Add-ManagedCredential` | Adds a credential to the Windows Credential Manager (Password Vault) |
| `Get-AllManagedCredentials` | Retrieves all credentials from Windows Credential Manager |
| `Get-ManagedCredential` | Retrieves credentials for a specific resource from Windows Credential Manager |
| `Get-ManagedConnectCredential` | Retrieves connection credentials using a naming convention (_user, _connect, _options) |
| `Save-ManagedConnectCredential` | Saves connection credentials to Windows Credential Manager with naming convention |

## Requirements

- **PowerShell** 5.1 or later
- **Windows** operating system (for CredManager functions - uses Windows.Security.Credentials)

## Installation

```powershell
# Clone or copy the module to a PowerShell module path
Copy-Item -Path ".\PSSomeAuthThings" -Destination "$env:USERPROFILE\Documents\PowerShell\Modules\PSSomeAuthThings" -Recurse

# Or import directly
Import-Module ".\PSSomeAuthThings\PSSomeAuthThings.psd1"
```

## Quick Start

### Working with credentials
```powershell
# Convert username/password to PSCredential
$cred = ConvertTo-PSCredential -username "admin" -password "P@ssw0rd"

# Get credentials using different modes
$auth1 = Get-AuthenticationCredentials -Username "user" -Password $securePass
$auth2 = Get-AuthenticationCredentials -Username "user" -EncryptedPasswordFile "C:\secure\pass.txt"
$auth3 = Get-AuthenticationCredentials -Credential $cred
```

### Password policy and validation
```powershell
# Create a password policy
$policy = New-PasswordPolicy -All -MinimalLength 12 -MustRespectCommonRulesCount 3

# Test a password against the policy
$result = Test-PasswordComplexity -Password "MyP@ssw0rd123" -Policy $policy
if (-not $result.Success) {
    Write-Host "Password validation failed:"
    $result.MissingRequirements | ForEach-Object { Write-Host "  - $_" }
}

# Interactively read a password with policy validation
$newPass = Read-PasswordWithPolicy -Prompt "Enter new password" -Policy $policy

# Read and confirm a new password
$confirmedPass = Read-NewPassword -Policy $policy -HeaderQuestion "Enter password" -RepeatQuestion "Confirm password"
```

### Windows Credential Manager integration
```powershell
# Add a credential
$cred = Get-Credential
Add-ManagedCredential -resource "MyApp" -credential $cred

# Or add with username/password
Add-ManagedCredential -resource "https://api.example.com" -username "admin" -Password "P@ssw0rd"

# Retrieve all credentials
$allCreds = Get-AllManagedCredentials
$allCreds | Format-Table Resource, UserName

# Retrieve credentials for a specific resource
$appCreds = Get-ManagedCredential -ressource "MyApp"

# Save connection credentials (structured naming)
$opts = @{ SSL = "true"; Timeout = "30" }
Save-ManagedConnectCredential -target "MyServer" -connect1 "192.168.1.10" -connect2 "4343" -credential $cred -options $opts

# Retrieve connection credentials
$conn = Get-ManagedConnectCredential -target "MyServer"
# Returns object with: credential, connect1, connect2, options
```

## Password Policy Details

### Policy Components

The `New-PasswordPolicy` function creates policy objects with these components:

1. **Common Rules** (optional requirements):
   - Numbers: `[0-9]+`
   - Uppercase letters: `[A-Z]+`
   - Lowercase letters: `[a-z]+`
   - Symbols (non-alphanumeric): `[^a-zA-Z0-9]+`

2. **Mandatory Rules** (must all be satisfied):
   - Minimum length (default: 8)
   - Maximum length (default: no limit)
   - Custom regex patterns

3. **Forbidden Rules** (must not match):
   - Custom regex patterns to disallow

4. **MinCommonRulesCount**:
   - Minimum number of common rules that must be satisfied
   - Example: If you have 4 common rules and set `MustRespectCommonRulesCount = 3`, the password must satisfy at least 3 of them

### Policy Examples

```powershell
# Simple policy: all common rules, min 12 characters
$policy1 = New-PasswordPolicy -All -MinimalLength 12

# Custom policy: 2 out of 3 common rules must be satisfied
$policy2 = New-PasswordPolicy -Numbers -Uppercase_Letters -Lowercase_Letters -MinimalLength 10 -MustRespectCommonRulesCount 2

# Policy with forbidden patterns
$forbiddenPatterns = @{
    "(?i)password" = "Password contains the word 'password'"
    "(?i)admin" = "Password contains the word 'admin'"
}
$policy3 = New-PasswordPolicy -All -MinimalLength 12 -ForbiddenRules $forbiddenPatterns

# Policy with custom mandatory rules
$mandatoryRules = @{
    "[!@#$%^&*]+" = "Must contain at least one special character (!@#$%^&*)"
}
$policy4 = New-PasswordPolicy -All -MinimalLength 10 -MandatoryRules $mandatoryRules
```

## Credential Manager Naming Convention

The `Save-ManagedConnectCredential` and `Get-ManagedConnectCredential` functions use a structured naming convention:

| Resource Pattern | Purpose | Stored As |
|------------------|---------|-----------|
| `{target}_user` | User credentials | UserName: username<br>Password: password |
| `{target}_connect` | Connection info | UserName: connect1 (e.g., hostname)<br>Password: connect2 (e.g., port) |
| `{target}_options` | Additional options | UserName: option key<br>Password: option value |

This allows structured storage and retrieval of complete connection configurations.

## Module Structure

```
PSSomeAuthThings/
├── PSSomeAuthThings.psd1    # Module manifest
├── PSSomeAuthThings.psm1    # Module loader (dot-sources all .ps1 files)
├── README.md                 # This file
├── LICENSE                   # PolyForm Noncommercial License
├── Credential/               # Credential and password utilities
│   ├── ConvertTo-PSCredential.ps1
│   ├── Get-AuthenticationCredentials.ps1
│   ├── New-PasswordPolicy.ps1
│   ├── Read-NewPassword.ps1
│   ├── Read-PasswordWithPolicy.ps1
│   └── Test-PasswordComplexity.ps1
└── CredManager/              # Windows Credential Manager integration
    ├── Add-ManagedCredential.ps1
    ├── Get-AllManagedCredentials.ps1
    ├── Get-ManagedCredential.ps1
    ├── Get-ManagedConnectCredential.ps1
    └── Save-ManagedConnectCredential.ps1
```

## Common Use Cases

### Enforce password policies in scripts
```powershell
# Define your organization's password policy
$orgPolicy = New-PasswordPolicy -All -MinimalLength 14 -MustRespectCommonRulesCount 4

# Use it when creating accounts
Write-Host "Creating new user account..."
$username = Read-Host "Username"
$password = Read-NewPassword -Policy $orgPolicy -HeaderQuestion "Enter password for $username"
```

### Store and retrieve API credentials
```powershell
# Store API credentials
$apiCred = Get-Credential -Message "Enter API credentials"
Add-ManagedCredential -resource "CompanyAPI" -credential $apiCred

# Later, retrieve them
$apiCreds = Get-ManagedCredential -ressource "CompanyAPI"
$apiKey = $apiCreds[0].Password
```

### Manage multiple server connections
```powershell
# Save server connection
$serverCred = Get-Credential -Message "Server admin credentials"
$serverOpts = @{
    Protocol = "SSH"
    Port = "22"
    Timeout = "30"
}
Save-ManagedConnectCredential -target "ProductionServer" -connect1 "prod.example.com" -connect2 "22" -credential $serverCred -options $serverOpts

# Retrieve and use
$conn = Get-ManagedConnectCredential -target "ProductionServer"
# Connect using $conn.credential, $conn.connect1, $conn.connect2, $conn.options
```

## Security Notes

- **Windows Credential Manager**: Credentials are encrypted by Windows using DPAPI (Data Protection API)
- **SecureString**: Passwords in memory are handled as SecureString when possible
- **Plain-text conversion**: Some functions require converting SecureString to plain text for API compatibility - use with caution
- **Credential storage**: Stored credentials are user-specific and tied to the Windows user profile

## Author

**Loïc Ade**

## License

This project is licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/). See the [LICENSE](LICENSE) file for details.

In short:
- **Non-commercial use only** — You may use, modify, and distribute this software for any non-commercial purpose.
- **Attribution required** — You must include a copy of the license terms with any distribution.
- **No warranty** — The software is provided as-is.
