function New-Networkv6Object {
    <#
    .SYNOPSIS
        Creates an IPv6 network object

    .DESCRIPTION
        Parses an IPv6 CIDR notation string into a network object with calculated
        properties: network address, prefix length, mask, first/last addresses, and
        host counts. Includes ToString(), ChangePrefix(), and Contains() methods.

    .PARAMETER InputString
        Network in CIDR notation (e.g. "2001:db8::/64") or IPv6 address.

    .PARAMETER PrefixLength
        Optional prefix length (used with InputString when not in CIDR format).

    .OUTPUTS
        [OrderedDictionary]. IPv6 network object with Network, PrefixLength, Mask, First, Last, UsableHosts, TotalHosts.

    .EXAMPLE
        $net = New-Networkv6Object "2001:db8::/48"

    .EXAMPLE
        $net = New-Networkv6Object "fe80::1" -PrefixLength 64
        $net.Contains("fe80::2")  # True

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$InputString,
        [int]$PrefixLength
    )
    
    Begin {
        # Parse input - expected format: "2001:db8::/64" or IP + separate PrefixLength
        if ($InputString -match "^(.+)/(\d+)$") {
            $sIPv6 = $Matches[1]
            $iPrefixLength = [int]$Matches[2]
        } elseif ($PrefixLength) {
            $sIPv6 = $InputString
            $iPrefixLength = $PrefixLength
        } else {
            throw [System.ArgumentException] "Invalid input: IPv6 network must include prefix length (e.g., '2001:db8::/64')"
        }
        
        # Validate the prefix length
        if ($iPrefixLength -lt 0 -or $iPrefixLength -gt 128) {
            throw [System.ArgumentException] "Prefix length must be between 0 and 128"
        }
        
        # Validate the IPv6
        $ipv6Regex = Get-IPRegex -IPv6 -FullLine
        if (-not ($sIPv6 -match $ipv6Regex)) {
            throw [System.ArgumentException] "Invalid IPv6 address format"
        }
    }
    
    Process {
        # Create the base IPv6 object
        $oIP = New-IPv6Object -InputObject $sIPv6
        
        # Calculate the network mask (128 bits)
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
        
        # Calculate the network address (IP AND mask)
        $aNetworkBytes = New-Object byte[] 16
        for ($i = 0; $i -lt 16; $i++) {
            $aNetworkBytes[$i] = $oIP.Value[$i] -band $aMask[$i]
        }
        $oNetworkIP = New-IPv6Object -InputObject $aNetworkBytes
        
        # Calculate the first and last address of the network
        $aFirstBytes = New-Object byte[] 16
        $aLastBytes = New-Object byte[] 16
        
        for ($i = 0; $i -lt 16; $i++) {
            $aFirstBytes[$i] = $aNetworkBytes[$i]
            $aLastBytes[$i] = $aNetworkBytes[$i] -bor (-bnot $aMask[$i])
        }
        
        # For IPv6, first/last are generally not reserved like in IPv4
        $oFirstIP = New-IPv6Object -InputObject $aFirstBytes
        $oLastIP = New-IPv6Object -InputObject $aLastBytes
        
        # Calculate the total number of addresses
        $iTotalHosts = if ($iPrefixLength -eq 128) {
            [bigint]1
        } else {
            [bigint]::Pow(2, 128 - $iPrefixLength)
        }
        
        # For IPv6, all addresses are generally usable
        $iUsableHosts = $iTotalHosts
        
        $hResult = [ordered]@{
            Network = $oNetworkIP
            PrefixLength = $iPrefixLength
            Mask = $aMask
            First = $oFirstIP
            Last = $oLastIP
            UsableHosts = $iUsableHosts
            TotalHosts = $iTotalHosts
            Type = "IPv6Network"
        }
        
        # ToString method
        $hResult | Add-Member -MemberType ScriptMethod -Name "ToString" -Force -Value {
            return $this.Network.ToString() + "/" + $this.PrefixLength.ToString()
        }
        
        # Method to change the prefix length
        $hResult | Add-Member -MemberType ScriptMethod -Name "ChangePrefix" -Force -Value {
            Param(
                [int]$NewPrefix
            )
            if ($NewPrefix -eq $this.PrefixLength) {
                return $this
            } elseif ($NewPrefix -lt $this.PrefixLength) {
                # Wider network
                return New-Networkv6Object -InputString $this.Network.ToString() -PrefixLength $NewPrefix
            } else {
                # Subdivision into smaller subnets
                $aResult = @()
                $iChangeSize = $NewPrefix - $this.PrefixLength
                $iNewRangesCount = [bigint]::Pow(2, $iChangeSize)
                
                # Calculate the increment between each subnet
                $iIncrement = [bigint]::Pow(2, 128 - $NewPrefix)
                
                for ([bigint]$i = 0; $i -lt $iNewRangesCount; $i++) {
                    # Calculate the new network address
                    $iNetworkValue = [bigint]0
                    for ($j = 0; $j -lt 16; $j++) {
                        $iNetworkValue = ($iNetworkValue -shl 8) + $this.Network.Value[$j]
                    }
                    
                    $iNewNetworkValue = $iNetworkValue + ($i * $iIncrement)
                    
                    # Convert to bytes
                    $aNewBytes = New-Object byte[] 16
                    for ($j = 15; $j -ge 0; $j--) {
                        $aNewBytes[$j] = [byte]($iNewNetworkValue -band 0xFF)
                        $iNewNetworkValue = $iNewNetworkValue -shr 8
                    }
                    
                    $oNewIP = New-IPv6Object -InputObject $aNewBytes
                    $aResult += New-Networkv6Object ($oNewIP.ToString() + "/" + $NewPrefix)
                }
                return $aResult
            }
        }
        
        # Method to check if an IP belongs to the network
        $hResult | Add-Member -MemberType ScriptMethod -Name "Contains" -Force -Value {
            Param(
                [object]$IPv6Address
            )
            $oTestIP = if ($IPv6Address -is [string]) {
                New-IPv6Object -InputObject $IPv6Address
            } else {
                $IPv6Address
            }
            
            # Apply the mask to the test IP and compare with the network
            for ($i = 0; $i -lt 16; $i++) {
                $maskedByte = $oTestIP.Value[$i] -band $this.Mask[$i]
                if ($maskedByte -ne $this.Network.Value[$i]) {
                    return $false
                }
            }
            return $true
        }
        
        $hResult.PSTypeNames.Insert(0, "IPv6Network")
        return $hResult
    }
}