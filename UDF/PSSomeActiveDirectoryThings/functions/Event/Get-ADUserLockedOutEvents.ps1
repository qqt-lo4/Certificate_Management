function Get-ADUserLockedOutEvents {
    <#
    .SYNOPSIS
        Retrieves account lockout events (4740) for a user or domain

    .DESCRIPTION
        Queries all domain controllers for security event 4740 (account lockout).
        Can filter by a specific AD user object or retrieve all lockout events
        for the domain. Returns parsed event data with timestamp, DC, and caller info.

    .PARAMETER ADObject
        The AD user object to filter lockout events for.

    .PARAMETER Domain
        The domain to query. Defaults to $env:USERDNSDOMAIN.

    .PARAMETER Credential
        Optional PSCredential for remote event log access.

    .PARAMETER StartTime
        Optional start time filter.

    .PARAMETER EndTime
        Optional end time filter.

    .OUTPUTS
        Hashtable[]. Array of parsed lockout events with DateTime, DC, User, and CallerComputerName.

    .EXAMPLE
        Get-ADUserLockedOutEvents -ADObject $user

    .EXAMPLE
        Get-ADUserLockedOutEvents -Domain "contoso.com" -StartTime (Get-Date).AddDays(-1)

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    [CmdletBinding(DefaultParameterSetName = "Domain")]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = "User")]
        [object]$ADObject,
        [Parameter(ParameterSetName = "Domain")]
        [string]$Domain = ($env:USERDNSDOMAIN),
        [pscredential]$Credential,
        [datetime]$StartTime,
        [datetime]$EndTime
    )
    if ($null -ne $ADObject)  {
        if (-not (Test-ContainsArray $ADObject.PSObject.Properties.Name @("objectsid", "msds-principalname"))) {
            Add-ADObjectProperties -ADObject $ADObject -Properties @("objectsid", "msds-principalname") | Out-Null
        }
    }
    $oEvents = if ($ADObject) {
        $PSBoundParameters.Remove("ADObject") | Out-Null
        Get-ADSecurityEvent -Id 4740 @PSBoundParameters -Data $ADObject.objectsid
    } else {
        Get-ADSecurityEvent -Id 4740 @PSBoundParameters
    }
    $aResult = @()
    foreach ($oEvent in $oEvents.Events) {
        $hEventResult = @{
            System = ([xml]$oEvent.ToXML()).Event.System
            EventData = ([xml]$oEvent.ToXml()).Event.EventData.Data | ForEach-Object -Begin { $hEventData = @{} } -Process { $hEventData[$_.Name] = $_."#text"} -End { $hEventData }
        }
        $oResult = @{
            DateTime = [datetime]$hEventResult.System.TimeCreated.SystemTime
            DC = $hEventResult.System.Computer
            User = $ADObject
            CallerComputerName = $hEventResult.EventData.TargetDomainName
            Event = $hEventResult
        }
        $oResult.PSTypeNames.Insert(0, "AD User Locked Out Event")
        $aResult += $oResult
    }
    return $aResult
}
