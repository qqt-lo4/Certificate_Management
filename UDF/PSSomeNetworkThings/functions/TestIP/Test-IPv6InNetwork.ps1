function Test-IPv6InNetwork {
    <#
    .SYNOPSIS
        Tests if an IPv6 address belongs to a network or range

    .DESCRIPTION
        Checks whether an IPv6 address falls within a specified network/prefix
        or an IPv6 range (start-end). Uses byte-level comparison for accuracy.

    .PARAMETER IPAddress
        The IPv6 address to test.

    .PARAMETER Network
        The network in CIDR notation (e.g. "2001:db8::/64") or network address.

    .PARAMETER PrefixLength
        The prefix length (used with Network when not in CIDR format).

    .PARAMETER Start
        The start IPv6 address of a range.

    .PARAMETER End
        The end IPv6 address of a range.

    .OUTPUTS
        [Boolean]. True if the IPv6 address is in the network or range.

    .EXAMPLE
        Test-IPv6InNetwork -IPAddress "2001:db8::1" -Network "2001:db8::/64"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

    [CmdletBinding(DefaultParameterSetName="IPAddress")]
    Param (
        [Parameter(Mandatory)]
        [string]$IPAddress,
        [Parameter(ParameterSetName="IPAddress", Mandatory)]
        [string]$Network,
        [Parameter(ParameterSetName="IPAddress")]
        [int]$PrefixLength,
        [Parameter(ParameterSetName="StartEnd", Mandatory=$True)]
        [string]$Start,
        [Parameter(ParameterSetName="StartEnd", Mandatory=$True)]
        [string]$End
    )
    
    Begin {
        $sNetworkRegex = Get-Networkv6Regex -FullLine
        $ipv6Regex = Get-IPRegex -IPv6 -FullLine
        
        # Validate the IPv6 address
        if (-not ($IPAddress -match $ipv6Regex)) {
            throw [System.ArgumentException] "IPAddress is not a valid IPv6 address"
        }
    }
    
    Process {
        if ($PSCmdlet.ParameterSetName -eq "IPAddress") {
            # Build the network string
            $sNetwork = if ($PrefixLength) {
                $Network + "/" + $PrefixLength
            } else {
                $Network
            }
            
            # Parse the network with regex
            if ($sNetwork -match $sNetworkRegex) {
                $sNetworkIP = $Matches.ipv6
                $iPrefixLength = [int]$Matches.prefixlength
            } else {
                throw [System.ArgumentException] "Network format is not valid (expected format: 2001:db8::/64)"
            }
            
            # Validate the network address
            if (-not ($sNetworkIP -match $ipv6Regex)) {
                throw [System.ArgumentException] "Network IP is not a valid IPv6 address"
            }
            
            try {
                # Create IPv6 objects
                $oIPAddress = New-IPv6Object -InputObject $IPAddress
                $oNetworkIP = New-IPv6Object -InputObject $sNetworkIP
                
                # Calculate the network mask (128 bits = 16 bytes)
                $aMask = New-Object byte[] 16
                $iBytesComplets = [int]($iPrefixLength / 8)
                $iBitsRestants = $iPrefixLength % 8
                
                # Fill complete bytes with 0xFF
                for ($i = 0; $i -lt $iBytesComplets; $i++) {
                    $aMask[$i] = 0xFF
                }
                
                # Fill the partial byte if needed
                if ($iBitsRestants -gt 0 -and $iBytesComplets -lt 16) {
                    $aMask[$iBytesComplets] = [byte](0xFF -shl (8 - $iBitsRestants))
                }
                
                # Apply the mask to both addresses and compare
                for ($i = 0; $i -lt 16; $i++) {
                    $maskedIP = $oIPAddress.Value[$i] -band $aMask[$i]
                    $maskedNetwork = $oNetworkIP.Value[$i] -band $aMask[$i]
                    
                    if ($maskedIP -ne $maskedNetwork) {
                        return $false
                    }
                }
                
                return $true
                
            } catch {
                throw [System.ArgumentException] "Error processing IPv6 addresses: $($_.Exception.Message)"
            }
            
        } else {
            # ParameterSet StartEnd - compare addresses between start and end
            
            # Validate start and end addresses
            if (-not ($Start -match $ipv6Regex)) {
                throw [System.ArgumentException] "Start is not a valid IPv6 address"
            }
            if (-not ($End -match $ipv6Regex)) {
                throw [System.ArgumentException] "End is not a valid IPv6 address"
            }
            
            try {
                $oIPAddress = New-IPv6Object -InputObject $IPAddress
                $oStartIP = New-IPv6Object -InputObject $Start
                $oEndIP = New-IPv6Object -InputObject $End
                
                # Compare byte by byte (big-endian)
                for ($i = 0; $i -lt 16; $i++) {
                    # Check if IP < Start
                    if ($oIPAddress.Value[$i] -lt $oStartIP.Value[$i]) {
                        return $false
                    }
                    # Check if IP > End
                    if ($oIPAddress.Value[$i] -gt $oEndIP.Value[$i]) {
                        return $false
                    }
                    # If bytes are different, we already have our answer
                    if ($oIPAddress.Value[$i] -ne $oStartIP.Value[$i] -or 
                        $oIPAddress.Value[$i] -ne $oEndIP.Value[$i]) {
                        # Continue comparison to be sure
                        if ($oIPAddress.Value[$i] -gt $oStartIP.Value[$i] -and 
                            $oIPAddress.Value[$i] -lt $oEndIP.Value[$i]) {
                            return $true
                        }
                    }
                }
                
                # If we get here, all byte-by-byte comparisons are equal
                return $true
                
            } catch {
                throw [System.ArgumentException] "Error processing IPv6 address range: $($_.Exception.Message)"
            }
        }
    }
}