function Get-W32TimeConfiguration {
    <#
    .SYNOPSIS
        Queries the Windows Time service configuration and status on a computer.

    .DESCRIPTION
        Combines three locale-independent sources to build a complete picture
        of the NTP synchronization state:

        - Registry: sync type, configured NTP servers, last successful sync
          time and source (LastGoodSampleInfo).
        - w32tm /query /source: current effective time source (raw output,
          no localized headers).
        - w32tm /stripchart /dataonly /samples:1: real-time offset measurement
          against the current source (numeric value on last line, not localized).

        All remote operations run through a single PowerShell remoting session
        (Invoke-Command) to avoid permission issues with direct w32tm or CIM
        remote calls.

    .PARAMETER ComputerName
        The computer to query. Accepts pipeline input. Defaults to localhost.

    .PARAMETER Credential
        Optional PSCredential for the remote PowerShell session.

    .OUTPUTS
        PSCustomObject with properties:
            ComputerName, Type, NtpServer, CurrentSource, LastSyncTime,
            LastSyncSource, Offset.

    .EXAMPLE
        Get-W32TimeConfiguration

    .EXAMPLE
        Get-W32TimeConfiguration -ComputerName DC01.contoso.com -Credential $cred

    .EXAMPLE
        "DC01","DC02","DC03" | Get-W32TimeConfiguration -Credential $cred

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        1.0.0 (2026-04-12) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias("Name", "DNSHostName")]
        [string]$ComputerName = $env:COMPUTERNAME,

        [AllowNull()]
        [PSCredential]$Credential
    )

    Process {
        $bIsLocal = ($ComputerName -eq $env:COMPUTERNAME) -or
                    ($ComputerName -eq 'localhost') -or
                    ($ComputerName -eq '.')

        $sbRemoteScript = {
            $sRegPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time'

            # NTP server values from registry / w32tm output may carry trailing
            # flags ("host.example.com,0x8"). Drop the flags for display.
            function Remove-NTPFlags {
                Param([string]$Value)
                if (-not $Value) { return $null }
                ($Value -split ',', 2)[0].Trim()
            }

            # --- Registry ---
            $oParams = Get-ItemProperty "$sRegPath\Parameters" -ErrorAction Stop
            $sType = $oParams.Type
            # NtpServer is a space-separated list; each entry is "host,flags"
            # (e.g. "time.windows.com,0x9 ntp.example.com,0x8").
            $sNtpServer = if ($oParams.NtpServer) {
                (($oParams.NtpServer -split '\s+') | ForEach-Object {
                    Remove-NTPFlags $_
                } | Where-Object { $_ }) -join ' '
            } else { $null }

            $dtLastSyncTime = $null
            $sLastSyncSource = $null
            $sLastGood = (Get-ItemProperty "$sRegPath\Config\Status" -ErrorAction SilentlyContinue).LastGoodSampleInfo
            if ($sLastGood) {
                $aParts = $sLastGood -split ';', 2
                if ($aParts[0] -match '^\d+$' -and [long]$aParts[0] -gt 0) {
                    $dtLastSyncTime = [datetime]::FromFileTimeUtc([long]$aParts[0]).ToLocalTime()
                }
                if ($aParts.Count -ge 2) { $sLastSyncSource = Remove-NTPFlags $aParts[1] }
            }

            # --- w32tm /query /source ---
            $aSourceOutput = w32tm /query /source 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw "w32tm /query /source failed: $(($aSourceOutput | Out-String).Trim())"
            }
            $sCurrentSource = Remove-NTPFlags (($aSourceOutput | Out-String).Trim())

            # --- w32tm /stripchart (offset against current source) ---
            # Only attempt if source looks like a resolvable FQDN
            # (avoids locale-dependent strings like "Local CMOS Clock", etc.).
            $sOffset = $null
            if ($sCurrentSource -match '\.') {
                $aStripOutput = w32tm /stripchart /computer:$sCurrentSource /dataonly /samples:1 2>&1
                if ($LASTEXITCODE -eq 0) {
                    $sLastLine = ($aStripOutput | Select-Object -Last 1).ToString().Trim()
                    if ($sLastLine -match ',\s*([+-][\d.]+s)') {
                        $sOffset = $Matches[1]
                    }
                } else {
                    Write-Warning "w32tm stripchart: $(($aStripOutput | Out-String).Trim())"
                }
            }

            [PSCustomObject][ordered]@{
                Type           = $sType
                NtpServer      = $sNtpServer
                CurrentSource  = $sCurrentSource
                LastSyncTime   = $dtLastSyncTime
                LastSyncSource = $sLastSyncSource
                Offset         = $sOffset
            }
        }

        if ($bIsLocal) {
            $oResult = & $sbRemoteScript
        } else {
            $hSessionParams = @{ ComputerName = $ComputerName }
            if ($Credential) { $hSessionParams['Credential'] = $Credential }

            $oSession = New-PSSession @hSessionParams -ErrorAction Stop
            try {
                $oResult = Invoke-Command -Session $oSession -ScriptBlock $sbRemoteScript -ErrorAction Stop
            } finally {
                Remove-PSSession $oSession -ErrorAction SilentlyContinue
            }
        }

        [PSCustomObject][ordered]@{
            ComputerName   = $ComputerName
            Type           = $oResult.Type
            NtpServer      = $oResult.NtpServer
            CurrentSource  = $oResult.CurrentSource
            LastSyncTime   = $oResult.LastSyncTime
            LastSyncSource = $oResult.LastSyncSource
            Offset         = $oResult.Offset
        }
    }
}
