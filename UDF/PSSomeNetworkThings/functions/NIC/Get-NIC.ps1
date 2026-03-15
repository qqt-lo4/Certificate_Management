function Get-NIC {
    <#
    .SYNOPSIS
        Gets network adapters with extended methods

    .DESCRIPTION
        Wraps Get-NetAdapter and enriches each adapter with script methods for
        accessing advanced properties, bindings, hardware info, statistics,
        DNS servers, connection profiles, IP addresses, and IP interfaces.
        Also adds a VPN detection property.

    .PARAMETER Name
        Filter by interface alias name.

    .PARAMETER IncludeHidden
        Include hidden adapters.

    .PARAMETER Physical
        Return only physical adapters.

    .PARAMETER CimSession
        CIM session(s) for remote execution.

    .PARAMETER ThrottleLimit
        Maximum concurrent operations.

    .PARAMETER AsJob
        Run as a background job.

    .PARAMETER InterfaceDescription
        Filter by interface description.

    .PARAMETER InterfaceIndex
        Filter by interface index.

    .PARAMETER Status
        Filter by adapter status (Disconnected or Up).

    .OUTPUTS
        [CimInstance[]]. Network adapter objects with added script methods and VPN property.

    .EXAMPLE
        Get-NIC -Physical -Status "Up"

    .EXAMPLE
        (Get-NIC -Name "Ethernet").DnsClientServerAddress("IPv4")

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

    [CmdletBinding(DefaultParameterSetName="ByName")]
    Param(
        [Parameter(ParameterSetName = "ByName")]
        [ValidateNotNull()]
        [Alias("ifAlias","InterfaceAlias")]
        [string[]]$Name,

        [Parameter(ParameterSetName = "ByIfIndex")]
        [Parameter(ParameterSetName = "ByInstanceID")]
        [Parameter(ParameterSetName = "ByName")]
        [switch]$IncludeHidden,

        [Parameter(ParameterSetName = "ByIfIndex")]
        [Parameter(ParameterSetName = "ByInstanceID")]
        [Parameter(ParameterSetName = "ByName")]
        [switch]$Physical,

        [Parameter(ParameterSetName = "ByIfIndex")]
        [Parameter(ParameterSetName = "ByInstanceID")]
        [Parameter(ParameterSetName = "ByName")]
        [ValidateNotNullOrEmpty()]
        [Alias("Session")]
        [Microsoft.Management.Infrastructure.CimSession[]]$CimSession,

        [Parameter(ParameterSetName = "ByIfIndex")]
        [Parameter(ParameterSetName = "ByInstanceID")]
        [Parameter(ParameterSetName = "ByName")]
        [Int32]$ThrottleLimit,

        [Parameter(ParameterSetName = "ByIfIndex")]
        [Parameter(ParameterSetName = "ByInstanceID")]
        [Parameter(ParameterSetName = "ByName")]
        [switch]$AsJob,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = "ByInstanceID")]
        [ValidateNotNull()]
        [Alias("ifDesc")]
        [string[]]$InterfaceDescription,

        [Parameter(Mandatory, ValueFromPipelineByPropertyName, ParameterSetName = "ByIfIndex")]
        [ValidateNotNull()]
        [Alias("ifIndex")]
        [UInt32[]]$InterfaceIndex,

        [ValidateSet("Disconnected", "Up")]
        [string]$Status
    )

    $PSBoundParameters.Remove("AdvancedProperties") | Out-Null
    $PSBoundParameters.Remove("AllAdvancedProperties") | Out-Null
    $PSBoundParameters.Remove("AdvancedPropertiesRegistryKeyword") | Out-Null
    $PSBoundParameters.Remove("Status") | Out-Null
    
    $aNIC = Get-NetAdapter @PSBoundParameters
    if ($Status) {
        $aNIC = $aNIC | Where-Object { $_.Status -eq $Status }
    }
    foreach ($oNIC in $aNIC) {
        $oNIC | Add-Member -MemberType ScriptMethod -Name "AdvancedProperties" -Value {
            Get-NetAdapterAdvancedProperty -Name $this.Name
        }
        $oNIC | Add-Member -MemberType ScriptMethod -Name "Binding" -Value {
            Get-NetAdapterBinding -Name $this.Name -ErrorAction SilentlyContinue
        }
        $oNIC | Add-Member -MemberType ScriptMethod -Name "HardwareInfo" -Value {
            Get-NetAdapterHardwareInfo -Name $this.Name -ErrorAction SilentlyContinue
        }
        $oNIC | Add-Member -MemberType ScriptMethod -Name "Statistics" -Value {
            Get-NetAdapterStatistics -Name $this.Name -ErrorAction SilentlyContinue
        }
        $oNIC | Add-Member -MemberType ScriptMethod -Name "DnsClientServerAddress" -Value {
            Param(
                [ValidateSet("", "IPv4", "IPv6")]
                [string]$AddressFamily = ""
            )
            if ($AddressFamily -eq "") {
                Get-DnsClientServerAddress -InterfaceAlias $this.Name -ErrorAction SilentlyContinue
            } else {
                Get-DnsClientServerAddress -InterfaceAlias $this.Name -AddressFamily $AddressFamily -ErrorAction SilentlyContinue 
            }
        }
        $oNIC | Add-Member -MemberType ScriptMethod -Name "NetConnectionProfile" -Value {
            Get-NetConnectionProfile -InterfaceAlias $this.Name -ErrorAction SilentlyContinue
        }
        $oNIC | Add-Member -MemberType ScriptMethod -Name "NetIPAddress" -Value {
            Param(
                [ValidateSet("", "IPv4", "IPv6")]
                [string]$AddressFamily = ""
            )
            if ($AddressFamily -eq "") {
                Get-NetIPAddress -InterfaceAlias $this.Name -ErrorAction SilentlyContinue
            } else {
                Get-NetIPAddress -InterfaceAlias $this.Name -AddressFamily $AddressFamily -ErrorAction SilentlyContinue 
            }
        }
        $oNIC | Add-Member -MemberType ScriptMethod -Name "NetIPConfiguration" -Value {
            Get-NetIPConfiguration -InterfaceAlias $this.Name -ErrorAction SilentlyContinue -Detailed
        }
        $oNIC | Add-Member -MemberType ScriptMethod -Name "NetIPInterface" -Value {
            Param(
                [ValidateSet("", "IPv4", "IPv6")]
                [string]$AddressFamily = ""
            )
            if ($AddressFamily -eq "") {
                Get-NetIPInterface -InterfaceAlias $this.Name -ErrorAction SilentlyContinue
            } else {
                Get-NetIPInterface -InterfaceAlias $this.Name -ErrorAction SilentlyContinue -AddressFamily $AddressFamily
            }
        }
        $oNIC | Add-Member -NotePropertyName "VPN" -NotePropertyValue (
            ($oNIC.InterfaceDescription -like "*pangp*") -or `
            ($oNIC.InterfaceDescription -like "*cisco*") -or `
            ($oNIC.InterfaceDescription -like "*juniper*") -or `
            ($oNIC.InterfaceDescription -like "Wintun*") -or `
            ($oNIC.InterfaceDescription -like "*vpn*")
        )
    }
    return $aNIC
}
