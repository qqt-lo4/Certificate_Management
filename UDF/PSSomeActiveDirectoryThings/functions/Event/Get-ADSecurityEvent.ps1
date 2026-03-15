function Get-ADSecurityEvent {
    <#
    .SYNOPSIS
        Retrieves security events from all domain controllers

    .DESCRIPTION
        Queries the Security event log on all domain controllers in the specified
        domain for events matching the given IDs, with optional time range and
        data filters. Returns a hashtable with query parameters and collected events.

    .PARAMETER Id
        The event ID(s) to search for.

    .PARAMETER Domain
        The domain to query. Defaults to $env:USERDNSDOMAIN.

    .PARAMETER Credential
        Optional PSCredential for remote event log access.

    .PARAMETER StartTime
        Optional start time filter for events.

    .PARAMETER EndTime
        Optional end time filter for events.

    .PARAMETER Data
        Optional data values to filter events by.

    .OUTPUTS
        System.Collections.Hashtable. Contains Id, Domain, Servers, Credential, and Events.

    .EXAMPLE
        Get-ADSecurityEvent -Id 4740 -Domain "contoso.com"
        # Gets all account lockout events

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory)]
        [int[]]$Id,
        [string]$Domain = ($env:USERDNSDOMAIN),
        [pscredential]$Credential,
        [datetime]$StartTime,
        [datetime]$EndTime,
        [string[]]$Data
    )
    $aDCServers = (Get-ADDomainControllers -Domain $Domain).Name
    $hResult = @{
        Id = $Id
        Domain = $Domain
        Servers = $aDCServers
        Credential = $Credential
    }
    $hFilter = @{
        LogName = 'Security'
        ID = $Id
    }
    if ($StartTime) { 
        $hResult.StartTime = $StartTime
        $hFilter.StartTime = $StartTime
    }
    if ($EndTime) { 
        $hResult.EndTime = $EndTime
        $hFilter.EndTime = $EndTime
    }
    if ($Data) {
        $hFilter.Data = $Data
    }
    $aEvents = @()
    foreach ($oServer in $aDCServers) {
        Write-Progress -Activity "Get events from $oServer"
        if ($Credential) {
            $aEvents += Get-WinEvent -ComputerName $oServer -Credential $Credential -FilterHashtable $hFilter -ErrorAction SilentlyContinue
        } else {
            $aEvents += Get-WinEvent -ComputerName $oServer -FilterHashtable $hFilter -ErrorAction SilentlyContinue
        }
    }
    Write-Progress -Activity "Finished getting events" -Completed
    $hResult.Events = $aEvents
    return $hResult
}