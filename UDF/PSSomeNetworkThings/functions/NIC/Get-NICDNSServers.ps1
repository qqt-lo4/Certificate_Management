function Get-NICDNSServers {
    <#
    .SYNOPSIS
        Gets DNS server addresses configured on network adapters

    .DESCRIPTION
        Retrieves DNS server addresses from network adapters using Get-NIC.
        Can filter by adapter name, index, status, and address family.
        Returns unique server addresses or detailed per-adapter info.

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

    .PARAMETER AddressFamily
        Filter by address family (IPv4 or IPv6).

    .PARAMETER Detailed
        Return full DNS client server address objects instead of just addresses.

    .OUTPUTS
        [String[]] or [CimInstance[]]. Unique DNS server addresses, or detailed objects with -Detailed.

    .EXAMPLE
        Get-NICDNSServers -Physical -Status "Up" -AddressFamily "IPv4"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

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
        [string]$Status,

        [ValidateSet("IPv4", "IPv6")]
        [string]$AddressFamily,

        [switch]$Detailed
    )

    $PSBoundParameters.Remove("AddressFamily") | Out-Null
    $PSBoundParameters.Remove("Detailed") | Out-Null
    $aNIC = Get-NIC @PSBoundParameters
    $aServerAddresses = if ($AddressFamily) {
        ($aNIC).DnsClientServerAddress($AddressFamily)
    } else {
        ($aNIC).DnsClientServerAddress()
    }
    if ($Detailed) {
        $aServerAddresses
    } else {
        $aServerAddresses.ServerAddresses | Select-Object -Unique
    }
}
