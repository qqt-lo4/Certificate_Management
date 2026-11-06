function Get-MSSqlInstance {
    <#
    .SYNOPSIS
        Lists the SQL Server Database Engine instances of a computer and their TLS configuration

    .DESCRIPTION
        Reads the instances declared in the registry (64-bit and 32-bit), and for each one:
        version and edition, Windows service (name, account, state), TCP port, encryption
        settings (ForceEncryption) and the certificate configured for TLS, looked up in
        Cert:\LocalMachine\My.

        Runs on the computer of the given PSSession, or locally when no session is given.
        Read only: nothing is changed.

    .PARAMETER Session
        A PSSession opened to the SQL Server computer (administrator rights needed to read the
        service and the registry). Local computer when omitted.

    .PARAMETER InstanceName
        Return only this instance (MSSQLSERVER for the default instance).

    .OUTPUTS
        [PSCustomObject] one per instance:
          ComputerName, InstanceName, InstanceId, Version, Edition,
          ServiceName, ServiceAccount, ServiceState,
          TcpEnabled, TcpPort (first static port, else dynamic port; 0 when unknown),
          ForceEncryption,
          CertificateThumbprint (configured, upper case; empty when none: SQL Server then
          presents a self-generated certificate),
          CertificateFound (the configured certificate is in LocalMachine\My),
          CertificateSubject, CertificateNotAfter, CertificateHasPrivateKey,
          CertificateRawData (to rebuild the X509Certificate2 on the caller side)

    .EXAMPLE
        Get-MSSqlInstance -Session $s | Format-Table InstanceName, ServiceState, TcpPort, CertificateSubject, CertificateNotAfter

    .EXAMPLE
        Get-MSSqlInstance -InstanceName MSSQLSERVER

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-11-06 - Loïc Ade
            - Initial release
    #>
    [CmdletBinding()]
    Param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$InstanceName
    )
    $sbScan = {
        param($InstanceName)
        $aRoots = @(
            "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Microsoft SQL Server"
        )
        foreach ($sRoot in $aRoots) {
            $oNames = Get-ItemProperty -Path "$sRoot\Instance Names\SQL" -ErrorAction SilentlyContinue
            if (-not $oNames) { continue }
            foreach ($oProp in ($oNames.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" })) {
                $sInstance = $oProp.Name
                if ($InstanceName -and ($sInstance -ne $InstanceName)) { continue }
                $sId = [string]$oProp.Value
                $sKey = "$sRoot\$sId"
                $oSetup = Get-ItemProperty -Path "$sKey\Setup" -ErrorAction SilentlyContinue
                $oNetLib = Get-ItemProperty -Path "$sKey\MSSQLServer\SuperSocketNetLib" -ErrorAction SilentlyContinue
                $oTcp = Get-ItemProperty -Path "$sKey\MSSQLServer\SuperSocketNetLib\Tcp" -ErrorAction SilentlyContinue
                $oIPAll = Get-ItemProperty -Path "$sKey\MSSQLServer\SuperSocketNetLib\Tcp\IPAll" -ErrorAction SilentlyContinue

                $sService = if ($sInstance -eq "MSSQLSERVER") { "MSSQLSERVER" } else { 'MSSQL$' + $sInstance }
                $oService = Get-CimInstance -ClassName Win32_Service -Filter ("Name='" + $sService + "'") -ErrorAction SilentlyContinue

                # Static port first, else the dynamic port; a value can list several ports
                $sPorts = if ("$($oIPAll.TcpPort)".Trim()) { "$($oIPAll.TcpPort)" } else { "$($oIPAll.TcpDynamicPorts)" }
                $iPort = 0
                $sFirstPort = @($sPorts.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[0-9]+$' })[0]
                if ($sFirstPort) { $iPort = [int]$sFirstPort }

                $sThumbprint = "$($oNetLib.Certificate)".Trim().ToUpper()
                $oCert = if ($sThumbprint) { Get-Item -Path "Cert:\LocalMachine\My\$sThumbprint" -ErrorAction SilentlyContinue } else { $null }

                [PSCustomObject]@{
                    ComputerName             = $env:COMPUTERNAME
                    InstanceName             = $sInstance
                    InstanceId               = $sId
                    Version                  = $oSetup.Version
                    Edition                  = $oSetup.Edition
                    ServiceName              = $sService
                    ServiceAccount           = $oService.StartName
                    ServiceState             = $oService.State
                    TcpEnabled               = ($oTcp.Enabled -eq 1)
                    TcpPort                  = $iPort
                    ForceEncryption          = ($oNetLib.ForceEncryption -eq 1)
                    CertificateThumbprint    = $sThumbprint
                    CertificateFound         = [bool]$oCert
                    CertificateSubject       = $oCert.Subject
                    CertificateNotAfter      = $oCert.NotAfter
                    CertificateHasPrivateKey = [bool]$oCert.HasPrivateKey
                    CertificateRawData       = if ($oCert) { $oCert.RawData } else { $null }
                }
            }
        }
    }
    if ($Session) {
        Invoke-Command -Session $Session -ScriptBlock $sbScan -ArgumentList $InstanceName |
            Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
    } else {
        & $sbScan $InstanceName
    }
}
