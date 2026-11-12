# PSSomeNetScalerThings

PowerShell utilities for read-only NetScaler ADC discovery through the Nitro REST API.

## Requirements

- PowerShell 5.1 or later
- NetScaler ADC Nitro API reachable over HTTPS
- A read-only Nitro API account
- A trusted HTTPS certificate on the ADC management endpoint

## Functions

| Function | Description |
|---|---|
| `Connect-NetScalerNitroSession` | Authenticates to Nitro and creates an in-memory web session |
| `Invoke-NetScalerNitroApi` | Sends a request through an authenticated Nitro session |
| `Get-NetScalerSSLVirtualServer` | Lists SSL and SSL_TCP LB/CS virtual servers |
| `Get-NetScalerSSLCertificateBinding` | Reads certificates bound to a virtual server |
| `Get-NetScalerContentSwitchHostname` | Extracts literal hostnames from bound CS policy rules |
| `Get-NetScalerSSLEndpoint` | Combines vServers, SNI bindings and host rules into endpoint candidates |
| `Disconnect-NetScalerNitroSession` | Logs out and expires the in-memory Nitro session |

Discovery is read-only. Wildcard names are not probed directly. If no SNI name or
explicit Content Switching hostname is found, the vServer name or VIP is returned
as a fallback; the presented certificate may then be the default vServer certificate.

The certificate check itself should be performed by the caller against each returned
`HostName` and `Port`, using the hostname as TLS SNI.

```powershell
$credential = Get-Credential
$session = Connect-NetScalerNitroSession -ManagementUri 'https://adc-mgmt.example.com' -Credential $credential
try {
	Get-NetScalerSSLEndpoint -Session $session
} finally {
	Disconnect-NetScalerNitroSession -Session $session
}
```