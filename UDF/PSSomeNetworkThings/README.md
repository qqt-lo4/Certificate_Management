# PSSomeNetworkThings

PowerShell module providing network utilities: IPv4/IPv6 object manipulation, subnet calculations, IP/network testing, NIC management, proxy configuration, MAC OUI lookup, WHOIS/RDAP queries, SSL/TLS testing, and string validation.

## Requirements

- PowerShell 5.1 or later
- Windows operating system
- Optional: PSSomeCoreThings module (for `Get-IPRegex`, `Get-MacAddressRegex`, `Get-DNSRegex`, `Convert-MatchInfoToHashtable`, etc.)

## Installation

Import the module from the `UDF` directory:

```powershell
Import-Module "G:\Scripts\PowerShell\UDF\PSSomeNetworkThings"
```

## Functions

### NewObject (7)

| Function | Description |
|---|---|
| `New-IPv4Object` | Creates an IPv4 address object from string or uint32 |
| `New-IPv6Object` | Creates an IPv6 address object from string or byte array |
| `New-IPv4RangeObject` | Creates an IPv4 range object (first-last) |
| `New-NetworkMaskv4Object` | Creates an IPv4 network mask object |
| `New-Networkv4Object` | Creates an IPv4 network object with subnet calculations |
| `New-Networkv6Object` | Creates an IPv6 network object with prefix calculations |
| `New-MACAddressObject` | Creates a MAC address object with formatting methods |

### NIC (2)

| Function | Description |
|---|---|
| `Get-NIC` | Gets network adapters with extended methods (bindings, DNS, IP, etc.) |
| `Get-NICDNSServers` | Gets DNS server addresses configured on network adapters |

### Other (5)

| Function | Description |
|---|---|
| `Get-MacOUI` | Gets OUI manufacturer information for a MAC address from IEEE database |
| `Update-OUIDatabase` | Updates the local IEEE OUI database |
| `Clear-OUICache` | Clears the in-memory OUI cache |
| `Test-ServerSSLSupport` | Tests SSL/TLS protocol support on a server |
| `Receive-InternetFile` | Downloads a file from the internet with progress indication |

### Proxy (4)

| Function | Description |
|---|---|
| `Get-SystemProxyConfiguration` | Gets the system-level proxy configuration (WinHTTP) |
| `Get-UserProxy` | Gets the current user's proxy configuration |
| `Set-InternetProxy` | Sets the Internet proxy configuration for the current user |
| `Resolve-ProxyPAC` | Resolves a proxy PAC file for a given URL |

### TestIP (5)

| Function | Description |
|---|---|
| `Test-IPInNetwork` | Tests if an IPv4 address belongs to a network or range |
| `Test-IPv6InNetwork` | Tests if an IPv6 address belongs to a network or range |
| `Test-IPInRange` | Checks if an IP/network/range belongs to specified IP ranges |
| `Test-IsRFC1918` | Checks if an IP belongs to RFC 1918 private ranges |
| `Test-IsPrivateIP` | Checks if an IP belongs to private ranges (RFC 1918 + RFC 6598) |
| `Test-PrivateOrDocumentedIP` | Tests if an IP belongs to any private or documented range |

### TestString (3)

| Function | Description |
|---|---|
| `Test-StringIsIP` | Tests if a string is a valid IP address, network, or range |
| `Test-StringIsDNSName` | Tests if a string is a valid DNS name |
| `Test-StringIsMacAddress` | Tests if a string is a valid MAC address |

### Whois (2)

| Function | Description |
|---|---|
| `Get-WhoIs` | Performs a WHOIS lookup for an IPv4 address via ARIN |
| `Invoke-RDAPQuery` | Performs an RDAP query for domains, IPs, or ASNs |

## License

This project is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE).

## Author

Loïc Ade
