function Restart-MSSqlInstance {
    <#
    .SYNOPSIS
        Restarts the service of a SQL Server instance and the dependent services that were running

    .DESCRIPTION
        Restarts the Windows service of the instance (MSSQLSERVER or MSSQL$<instance>). The
        dependent services (SQL Server Agent...) have to be stopped first: those that were
        running are started again afterwards.

        The instance is unavailable during the restart: connections are cut.

    .PARAMETER Session
        A PSSession opened to the SQL Server computer (administrator rights). Local computer
        when omitted.

    .PARAMETER InstanceName
        Name of the instance (MSSQLSERVER for the default instance).

    .OUTPUTS
        [PSCustomObject] with Success, Error, ServiceName, ServiceState, DependentServices
        (names of the dependent services started again).

    .EXAMPLE
        Restart-MSSqlInstance -Session $s -InstanceName MSSQLSERVER

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
        [Parameter(Mandatory)]
        [string]$InstanceName
    )
    $sbRestart = {
        param($InstanceName)
        $sService = if ($InstanceName -eq "MSSQLSERVER") { "MSSQLSERVER" } else { 'MSSQL$' + $InstanceName }
        $hResult = [ordered]@{ Success = $false; Error = $null; ServiceName = $sService; ServiceState = $null; DependentServices = @() }
        try {
            $oService = Get-Service -Name $sService -ErrorAction Stop
            $aDependents = @($oService.DependentServices | Where-Object { $_.Status -eq "Running" } | ForEach-Object { $_.Name })
            Restart-Service -Name $sService -Force -ErrorAction Stop
            foreach ($sDependent in $aDependents) {
                Start-Service -Name $sDependent -ErrorAction Stop
            }
            $hResult.DependentServices = $aDependents
            $hResult.Success = $true
        } catch {
            $hResult.Error = $_.Exception.Message
        }
        $hResult.ServiceState = "$((Get-Service -Name $sService -ErrorAction SilentlyContinue).Status)"
        [PSCustomObject]$hResult
    }
    if ($Session) {
        Invoke-Command -Session $Session -ScriptBlock $sbRestart -ArgumentList $InstanceName |
            Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName
    } else {
        & $sbRestart $InstanceName
    }
}
