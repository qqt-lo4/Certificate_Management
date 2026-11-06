# PSSomeMSSqlThings

Microsoft SQL Server helpers: instance discovery and TLS certificate renewal.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![License](https://img.shields.io/badge/License-PolyForm%20Noncommercial-lightgrey)

## Functions

| Function | Description |
|---|---|
| `Get-MSSqlInstance` | Lists the instances of a computer (local or through a PSSession): version, service, TCP port, ForceEncryption and configured TLS certificate. Read only |
| `Set-MSSqlCertificate` | Prepares a new TLS certificate for an instance without restarting it: PFX import into LocalMachine\My, read access to the private key for the service account, thumbprint in the instance configuration |
| `Restart-MSSqlInstance` | Restarts the service of an instance and the dependent services that were running |

SQL Server reads its certificate when the service starts: after `Set-MSSqlCertificate`, the new certificate is used at the next restart of the instance. The encryption settings (ForceEncryption...) are never changed.

The certificate presented by an instance on the network can be read with `Get-CertificateFromSqlServer` (PSSomeCertificatesThings).

## Example

```powershell
$s = New-PSSession -ComputerName sql01
Get-MSSqlInstance -Session $s | Format-Table InstanceName, ServiceState, TcpPort, CertificateSubject, CertificateNotAfter
Set-MSSqlCertificate -Session $s -InstanceName MSSQLSERVER -PfxPath C:\certs\sql01.pfx -Password (Read-Host -AsSecureString)
Restart-MSSqlInstance -Session $s -InstanceName MSSQLSERVER   # service interruption
```

## Author

**Loïc Ade**

## License

This project is licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0/). See the [LICENSE](LICENSE) file for details.
