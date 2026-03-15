function Test-IPInNetwork {
    <#
    .SYNOPSIS
        Tests if an IP address belongs to a network or range

    .DESCRIPTION
        Checks whether an IPv4 address falls within a specified network/subnet
        or an IP range (start-end). Supports CIDR notation and dotted mask.

    .PARAMETER IPAddress
        The IP address to test.

    .PARAMETER Network
        The network address (e.g. "192.168.1.0/24" or "192.168.1.0").

    .PARAMETER SubnetMask
        The subnet mask in dotted notation (used with Network).

    .PARAMETER Start
        The start IP of a range.

    .PARAMETER End
        The end IP of a range.

    .OUTPUTS
        [Boolean]. True if the IP is in the network or range.

    .EXAMPLE
        Test-IPInNetwork -IPAddress "192.168.1.50" -Network "192.168.1.0/24"

    .EXAMPLE
        Test-IPInNetwork -IPAddress "10.0.0.5" -Start "10.0.0.1" -End "10.0.0.254"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

    [CmdletBinding(DefaultParameterSetName="IPAddress")]
    Param (
        [Parameter(Mandatory)]
        [IPAddress]$IPAddress,

        [Parameter(ParameterSetName="IPAddress", Mandatory)]
        [string]$Network,

        [Parameter(ParameterSetName="IPAddress")]
        [Alias('Mask')]
        [ValidateNotNull()]
        [string]$SubnetMask,

        [Parameter(ParameterSetName="StartEnd",Mandatory=$True)]
        [IPAddress]$Start,

        [Parameter(ParameterSetName="StartEnd",Mandatory=$True)]
        [IPAddress]$End
    )
    Begin {
        $sNetworkRegex = Get-Networkv4Regex -FullLine
        $oIPAddress = [ipaddress]$IPAddress
    }
    Process {
        if ($PSCmdlet.ParameterSetName -eq "IPAddress") {
            $sNetwork = if ($SubnetMask) {
                $Network + "/" + $SubnetMask
            } else {
                $Network
            }
            $oNetwork, $oMask = if ($sNetwork -match $sNetworkRegex) {
                $oN = [ipaddress]$Matches.ip
                $oM = if ($Matches.mask) {
                    [ipaddress]$Matches.mask
                } else {
                    $iMask = $Matches.masklength -as [int]
                    $sBinaryMask = ("1"*$iMask+"0"*(32 - $iMask))
                    $aBytesMask = @(
                        [convert]::ToByte($sBinaryMask.SubString(0,8),2),
                        [convert]::ToByte($sBinaryMask.SubString(8,8),2),
                        [convert]::ToByte($sBinaryMask.SubString(16,8),2),
                        [convert]::ToByte($sBinaryMask.SubString(24,8),2)
                    )
                    New-Object -TypeName Net.IPAddress -ArgumentList @(,$aBytesMask)
                }
                $oN, $oM
            } else {
                throw [System.ArgumentOutOfRangeException] "Network or mask is not valid"
            }
            return ($oNetwork.Address -band $oMask.Address) -eq ($oIPAddress.Address -band $oMask.Address)
        } else {
            $oStartIP = [ipaddress]$Start
            $oEndIP = [ipaddress]$End
            return ($oIPAddress.Address -ge $oStartIP.Address) -and ($oIPAddress.Address -le $oEndIP.Address)
        }
    }
}
