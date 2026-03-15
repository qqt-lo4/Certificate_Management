# PSSomeActiveDirectoryThings

A PowerShell module for Active Directory management: user, computer, group and object operations, domain and forest queries, LAPS password management, event log analysis, and CLI dialogs for AD object selection. Uses DirectoryServices (ADSI/LDAP) without requiring the ActiveDirectory PowerShell module.

## Features

### Classes (1 function)

| Function | Description |
|----------|-------------|
| `Get-ADObjectClasses` | Retrieves all object class definitions from the AD schema |

### Computer (5 functions)

| Function | Description |
|----------|-------------|
| `Get-ADComputer` | Searches for AD computer objects with flexible filtering |
| `Get-ADComputerDomain` | Retrieves the domain name of an AD computer object |
| `Expand-ComputerIPInfo` | Expands a computer object with resolved IP address information |
| `Show-ComputerBasicInfo` | Displays formatted basic information for an AD computer |
| `Show-LAPSPassword` | Displays the LAPS password for one or more computers with colored output |

### Container (1 function)

| Function | Description |
|----------|-------------|
| `Get-ADContainerObjects` | Lists child objects of an AD container with optional class filtering |

### Dialog (2 functions)

| Function | Description |
|----------|-------------|
| `Find-ADObject` | Interactive AD object search with identity parsing, domain selection, and result navigation |
| `Select-CLIDialogADObject` | CLI dialog for searching and selecting AD objects with pagination |

### Domain (6 functions)

| Function | Description |
|----------|-------------|
| `Connect-DirectoryEntry` | Creates an authenticated DirectoryEntry connection to an AD path |
| `Get-CurrentDomainPath` | Returns the LDAP root path of the current domain |
| `Get-CurrentADForest` | Returns the current Active Directory forest name |
| `Get-CurrentADForestDomains` | Retrieves all domains in the current AD forest |
| `Get-ADDomainControllers` | Lists domain controllers for a specified domain |
| `Get-DirectoryEntry` | Creates a DirectoryEntry object for an AD path with optional credentials |

### Event (2 functions)

| Function | Description |
|----------|-------------|
| `Get-ADSecurityEvent` | Queries security event logs from domain controllers for specific event IDs |
| `Get-ADUserLockedOutEvents` | Retrieves account lockout events (Event ID 4740) for a user |

### Forest (1 function)

| Function | Description |
|----------|-------------|
| `Get-ADForest` | Retrieves forest information using the Forest DirectoryContext |

### Group (5 functions)

| Function | Description |
|----------|-------------|
| `Get-ADGroup` | Searches for AD group objects with flexible filtering |
| `Get-GroupMembers` | Retrieves all members of an AD group |
| `Add-ADGroupMember` | Adds a member to an AD group |
| `Remove-ADGroupMember` | Removes a member from an AD group |
| `Show-GroupBasicInfo` | Displays formatted basic information for an AD group |

### LAPS (3 functions)

| Function | Description |
|----------|-------------|
| `Get-ADComputerLAPS` | Retrieves LAPS password information (legacy and Windows LAPS) for computers |
| `Expand-ComputerLAPSInfo` | Expands computer objects with LAPS password attributes |
| `Set-LAPSPasswordExpiration` | Sets the LAPS password expiration date for a computer |

### Object (21 functions)

| Function | Description |
|----------|-------------|
| `Get-ADObject` | Core function for searching AD objects with identity, filter, LDAP filter, or path |
| `ConvertTo-ADObject` | Converts DirectoryEntry or SearchResult objects to typed AD objects |
| `ConvertFrom-ADSPath` | Parses an ADS path into protocol, server, and DN components |
| `Get-ADDNObject` | Retrieves an AD object by distinguished name with optional credentials |
| `Add-ADObjectProperties` | Adds additional properties to an existing AD object |
| `Add-ADObjectMemberOf` | Adds an AD object to one or more groups |
| `Get-ADObjectManager` | Retrieves the manager of an AD object as a full AD object |
| `Set-ADObjectManager` | Sets or clears the manager attribute of an AD object |
| `Get-ADObjectMemberOf` | Retrieves group memberships for an AD object |
| `Get-ADObjectListProperty` | Retrieves a multi-valued property as a list of AD objects |
| `Get-ADObjectDirectReports` | Retrieves the direct reports of an AD object |
| `Set-ADObjectAttribute` | Sets a single attribute value on an AD object |
| `Set-ADObjectExpiration` | Sets or clears the account expiration date |
| `Set-ADObjectUserAccountControlValue` | Sets or clears a UserAccountControl flag |
| `Disable-ADObject` | Disables an AD account |
| `Enable-ADObject` | Enables a disabled AD account |
| `Test-ADObjectDisabled` | Tests whether an AD account is disabled |
| `Test-ADObjectEnabled` | Tests whether an AD account is enabled |
| `Test-ADObjectExpired` | Tests whether an AD account has expired |
| `Show-ADObjectInfo` | Displays formatted basic information for any AD object |
| `Show-ADObjectAllInfo` | Displays all properties of an AD object with colored DN highlighting |

### Other (10 functions + 1 enum)

| Function | Description |
|----------|-------------|
| `ADS_USER_FLAG_ENUM` | Enumeration of Active Directory UserAccountControl flag values |
| `Convert-ADDateTime` | Converts AD large integer date/time values to readable format |
| `Convert-ADObjectValue` | Converts raw AD property values to typed wrapper objects |
| `Convert-ADUACBit` | Tests whether a specific UserAccountControl flag is set |
| `Convert-ADUserToUserPrincipal` | Converts an AD user object to a UserPrincipal object |
| `ConvertFrom-CategoryDN` | Extracts the CN value from a category distinguished name |
| `ConvertFrom-DN` | Extracts the domain name from a distinguished name |
| `Group-DNByDomain` | Groups a list of distinguished names by domain |
| `Read-ADObjectIdentity` | Reads and validates an AD object identity from input or user prompt |
| `Split-DN` | Splits a distinguished name into its individual components |
| `Test-StringIsADObjectIdentity` | Tests whether a string matches a recognized AD object identity format |

### User (14 functions)

| Function | Description |
|----------|-------------|
| `Get-ADUser` | Searches for AD user objects |
| `Expand-UserLogonInfo` | Expands an AD user object with computed logon properties |
| `Show-UserBasicInfo` | Displays formatted basic information for an AD user |
| `Show-UserLogonInfo` | Displays formatted logon information for an AD user |
| `Test-ADUserPasswordNeverExpires` | Tests whether a user's password is set to never expire |
| `Test-ADUserPasswordCannotChange` | Tests whether a user is prevented from changing their password |
| `Test-ADUserPasswordExpired` | Tests whether a user's password has expired |
| `Test-ADUserPasswordMustChange` | Tests whether a user must change their password at next logon |
| `Test-ADUserLockedOut` | Tests whether a user account is locked out |
| `Get-ADUserCantLogReasons` | Returns the reasons a user cannot log on |
| `Reset-ADUserPassword` | Resets a user's password and unlocks the account |
| `Unlock-User` | Unlocks one or more locked AD user accounts |
| `Add-ADUserManagedUsers` | Sets a user as the manager of one or more AD users |
| `Update-ADUserManager` | Updates the manager for one or more AD users |

## Requirements

- **PowerShell** 5.1 or later
- **Windows** operating system
- **PSSomeDataThings** module (for data manipulation utilities)
- Network access to Active Directory domain controllers
- Appropriate AD permissions for read/write operations
- Administrator privileges may be required for:
  - LAPS password retrieval
  - Account modifications (disable, enable, password reset, unlock)
  - Security event log queries on domain controllers

## Installation

```powershell
# Clone or copy the module to a PowerShell module path
Copy-Item -Path ".\PSSomeActiveDirectoryThings" -Destination "$env:USERPROFILE\Documents\PowerShell\Modules\PSSomeActiveDirectoryThings" -Recurse

# Or import directly
Import-Module ".\PSSomeActiveDirectoryThings\PSSomeActiveDirectoryThings.psd1"
```

## Quick Start

### Search for users and computers
```powershell
# Find a user by identity
$user = Get-ADUser -Identity "jdoe"

# Search with LDAP filter
$users = Get-ADUser -LDAPFilter "(department=IT)" -Properties "mail", "title"

# Find a computer
$computer = Get-ADComputer -Identity "WORKSTATION01"
```

### Display user information
```powershell
# Show basic user info with colored output
Show-UserBasicInfo -User $user

# Show logon status (locked, expired, disabled, etc.)
Show-UserLogonInfo -User $user

# Get reasons why a user can't log on
Get-ADUserCantLogReasons -ADUser $user
```

### Manage accounts
```powershell
# Unlock a locked account
Unlock-User -User $user

# Reset a password
Reset-ADUserPassword -User $user -Password $securePassword -MustChangePassword

# Disable/Enable an account
Disable-ADObject -ADObject $user
Enable-ADObject -ADObject $user
```

### Work with groups
```powershell
# Get group members
$members = Get-GroupMembers -ADGroup $group

# Add/Remove members
Add-ADGroupMember -ADGroup $group -Member $user
Remove-ADGroupMember -ADGroup $group -Member $user
```

### LAPS password management
```powershell
# Get LAPS password for a computer
$laps = Get-ADComputerLAPS -Computer $computer

# Display LAPS password with colored output
Show-LAPSPassword -Computer $computer
```

## Module Structure

```
PSSomeActiveDirectoryThings/
├── PSSomeActiveDirectoryThings.psd1    # Module manifest
├── PSSomeActiveDirectoryThings.psm1    # Module loader (dot-sources all .ps1 files)
├── README.md                           # This file
├── LICENSE                             # PolyForm Noncommercial License
├── Classes/                            # AD schema class queries
├── Computer/                           # Computer object operations
├── Container/                          # Container enumeration
├── Dialog/                             # Interactive CLI dialogs
├── Domain/                             # Domain and connection utilities
├── Event/                              # Security event log queries
├── Forest/                             # Forest information
├── Group/                              # Group management
├── LAPS/                               # Local Administrator Password Solution
├── Object/                             # Core AD object operations
├── Other/                              # Conversion utilities and helpers
└── User/                               # User account management
```

## Author

**Loïc Ade**

## License

This project is licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/). See the [LICENSE](LICENSE) file for details.

In short:
- **Non-commercial use only** — You may use, modify, and distribute this software for any non-commercial purpose.
- **Attribution required** — You must include a copy of the license terms with any distribution.
- **No warranty** — The software is provided as-is.
