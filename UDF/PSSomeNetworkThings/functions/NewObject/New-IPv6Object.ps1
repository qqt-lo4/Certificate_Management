function New-IPv6Object {
    <#
    .SYNOPSIS
        Creates an IPv6 address object

    .DESCRIPTION
        Converts a string IPv6 address or byte array into a custom IPv6 object
        with methods for display (ToString, ToFullString) and type checking
        (IsLoopback, IsLinkLocal).

    .PARAMETER InputObject
        An IPv6 address string (e.g. "fe80::1") or a 16-byte array.

    .OUTPUTS
        [Hashtable]. IPv6 object with Value (byte[]), Type, ToString(), ToFullString(), IsLoopback(), IsLinkLocal().

    .EXAMPLE
        $ipv6 = New-IPv6Object "::1"

    .EXAMPLE
        $ipv6 = New-IPv6Object "fe80::1"
        $ipv6.IsLinkLocal()  # True

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

    Param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [object]$InputObject
    )
    
    [byte[]]$aIPResult = if ($InputObject -is [byte[]]) {
        if ($InputObject.Length -eq 16) {
            $InputObject
        } else {
            throw [System.ArgumentException] "Byte array must be 16 bytes long for IPv6"
        }
    } elseif ($InputObject -is [string]) {
        # Use Get-IPRegex to validate the IPv6
        $ipv6Regex = Get-IPRegex -IPv6 -FullLine
        if ($InputObject -match $ipv6Regex) {
            try {
                # Use .NET to parse the IPv6
                $ipAddress = [System.Net.IPAddress]::Parse($InputObject)
                if ($ipAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                    $ipAddress.GetAddressBytes()
                } else {
                    throw [System.ArgumentException] "Not an IPv6 address"
                }
            } catch {
                throw [System.ArgumentException] "Input Object is not a valid IPv6 string: $($_.Exception.Message)"
            }
        } else {
            throw [System.ArgumentException] "Input Object is not a valid IPv6 string format"
        }
    } else {
        throw [System.ArgumentException] "Input Object is not a valid object (expected string or byte array)"
    }
    
    $hResult = @{
        Value = $aIPResult
        Type = "IPv6"
    }
    
    # ToString method to display the IPv6
    $hResult | Add-Member -MemberType ScriptMethod -Name "ToString" -Force -Value {
        $hexGroups = @()
        for ($i = 0; $i -lt 16; $i += 2) {
            $group = ([uint16]($this.Value[$i]) -shl 8) + $this.Value[$i + 1]
            $hexGroups += $group.ToString("x")
        }
        
        # Reconstruct the IPv6 address
        $ipv6String = $hexGroups -join ":"
        
        # Simplification with :: (zero compression rule)
        # Find the longest sequence of consecutive "0" groups
        $zeroPattern = ":0(:0)*"
        if ($ipv6String -match $zeroPattern) {
            $matches = [regex]::Matches($ipv6String, $zeroPattern)
            if ($matches.Count -gt 0) {
                $longestMatch = $matches | Sort-Object Length -Descending | Select-Object -First 1
                $replacement = if ($longestMatch.Index -eq 0) { "::" } 
                               elseif ($longestMatch.Index + $longestMatch.Length -eq $ipv6String.Length) { "::" }
                               else { "::" }
                $ipv6String = $ipv6String.Remove($longestMatch.Index, $longestMatch.Length).Insert($longestMatch.Index, $replacement)
            }
        }
        
        # Clean up double :: that may appear
        $ipv6String = $ipv6String -replace ":::", "::"
        
        return $ipv6String
    }
    
    # Method to get the full representation (without compression)
    $hResult | Add-Member -MemberType ScriptMethod -Name "ToFullString" -Force -Value {
        $hexGroups = @()
        for ($i = 0; $i -lt 16; $i += 2) {
            $group = ([uint16]($this.Value[$i]) -shl 8) + $this.Value[$i + 1]
            $hexGroups += $group.ToString("x4")  # Always 4 digits
        }
        return $hexGroups -join ":"
    }
    
    # Method to check if it's a loopback address
    $hResult | Add-Member -MemberType ScriptMethod -Name "IsLoopback" -Force -Value {
        # ::1 in bytes
        $loopback = @(0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1)
        for ($i = 0; $i -lt 16; $i++) {
            if ($this.Value[$i] -ne $loopback[$i]) {
                return $false
            }
        }
        return $true
    }
    
    # Method to check if it's a link-local address
    $hResult | Add-Member -MemberType ScriptMethod -Name "IsLinkLocal" -Force -Value {
        # Link-local starts with fe80::/10
        return ($this.Value[0] -eq 0xfe) -and (($this.Value[1] -band 0xc0) -eq 0x80)
    }
    
    $hResult.PSTypeNames.Insert(0, "IPv6 Address")
    return $hResult
}