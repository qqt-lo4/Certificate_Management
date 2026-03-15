function Test-IPInRange {
    <#
    .SYNOPSIS
        Checks if an IP address, network or range belongs to specified IP ranges.
    
    .DESCRIPTION
        Generic function that determines if an IP address, DNS name, CIDR network or IP range 
        belongs to a list of specified IP ranges.
        
        Returns:
        - "Yes" : If the entire input is within the specified ranges
        - "No" : If the entire input is outside the specified ranges
        - "Partial" : If only part of the input range overlaps with specified ranges
    
    .PARAMETER IPAddress
        The IP address, DNS name, CIDR network or range to check as a string.
        Accepted formats:
        - Single IP: "192.168.1.1"
        - DNS name: "server.domain.com"
        - CIDR network: "192.168.1.0/24"
        - Range: "192.168.1.1-192.168.1.254" or "192.168.1.1 - 192.168.1.254"
    
    .PARAMETER Ranges
        Array of hashtables defining the ranges to check against.
        Each hashtable should contain:
        - Name: String describing the range (e.g., "10.0.0.0/8")
        - Start: String with the start IP address
        - End: String with the end IP address
    
    .EXAMPLE
        $ranges = @(
            @{ Name = "10.0.0.0/8"; Start = "10.0.0.0"; End = "10.255.255.255" }
        )
        Test-IPInRange -IPAddress "10.0.0.1" -Ranges $ranges
        # Returns: Yes
    
    .EXAMPLE
        $ranges = @(
            @{ Name = "192.168.0.0/16"; Start = "192.168.0.0"; End = "192.168.255.255" }
        )
        Test-IPInRange -Address "server.domain.com" -Ranges $ranges
        # Returns: Yes (if DNS resolves to an IP in range)

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [Alias("Address")]
        [string]$IPAddress,
        
        [Parameter(Mandatory = $true)]
        [hashtable[]]$Ranges
    )
    
    Begin {
        # Internal function to test if an IP (as bytes) is in any of the ranges
        function Test-OctetsInRange {
            param(
                [byte[]]$octets,
                [hashtable[]]$ranges
            )
            
            foreach ($range in $ranges) {
                $startOctets = ([System.Net.IPAddress]::Parse($range.Start)).GetAddressBytes()
                $endOctets = ([System.Net.IPAddress]::Parse($range.End)).GetAddressBytes()
                
                $isInRange = $true
                for ($i = 0; $i -lt 4; $i++) {
                    if ($octets[$i] -lt $startOctets[$i] -or $octets[$i] -gt $endOctets[$i]) {
                        $isInRange = $false
                        break
                    }
                    # If not equal, we can determine the result early
                    if ($octets[$i] -gt $startOctets[$i] -and $octets[$i] -lt $endOctets[$i]) {
                        break
                    }
                }
                
                if ($isInRange) {
                    return $true
                }
            }
            
            return $false
        }
        
        # Function to convert IP to UInt32
        function ConvertTo-IPUInt32 {
            param([System.Net.IPAddress]$IP)
            
            $octets = $IP.GetAddressBytes()
            [Array]::Reverse($octets)
            return [System.BitConverter]::ToUInt32($octets, 0)
        }
        
        # Function to check if two ranges overlap
        function Test-RangeOverlap {
            param(
                [uint32]$Range1Start,
                [uint32]$Range1End,
                [uint32]$Range2Start,
                [uint32]$Range2End
            )
            
            return (($Range1Start -le $Range2End) -and ($Range1End -ge $Range2Start))
        }
        
        # Function to check if a range is entirely contained within another
        function Test-RangeContains {
            param(
                [uint32]$ContainerStart,
                [uint32]$ContainerEnd,
                [uint32]$InnerStart,
                [uint32]$InnerEnd
            )
            
            return (($InnerStart -ge $ContainerStart) -and ($InnerEnd -le $ContainerEnd))
        }
        
        # Convert provided ranges to UInt32 for easier comparison
        $ConvertedRanges = @()
        foreach ($range in $Ranges) {
            $ConvertedRanges += @{
                Name = $range.Name
                Start = ConvertTo-IPUInt32 -IP ([System.Net.IPAddress]::Parse($range.Start))
                End = ConvertTo-IPUInt32 -IP ([System.Net.IPAddress]::Parse($range.End))
            }
        }
    }
    
    Process {
        $input = $IPAddress.Trim()
        
        # Check if it's a CIDR network
        $networkRegex = Get-Networkv4Regex -FullLine
        if ($input -match $networkRegex) {
            $ip = $matches['ip']
            
            # Determine mask in bits
            if ($matches['masklength']) {
                $maskBits = [int]$matches['masklength']
            }
            elseif ($matches['mask']) {
                # Convert mask to CIDR notation
                $maskIP = [System.Net.IPAddress]::Parse($matches['mask'])
                $maskBytes = $maskIP.GetAddressBytes()
                [Array]::Reverse($maskBytes)
                $maskInt = [System.BitConverter]::ToUInt32($maskBytes, 0)
                $maskBits = [System.Convert]::ToString($maskInt, 2).Replace('0','').Length
            }
            
            # Validate IP address
            [IPAddress]$ipObj = $null
            if (-not [System.Net.IPAddress]::TryParse($ip, [ref]$ipObj)) {
                Write-Error "IP address '$ip' is not valid."
                return "No"
            }
            
            # Calculate network start and end addresses
            $ipInt = ConvertTo-IPUInt32 -IP $ipObj
            $mask = [uint32]([Math]::Pow(2, 32) - [Math]::Pow(2, 32 - $maskBits))
            $networkInt = $ipInt -band $mask
            $broadcastInt = $networkInt -bor (-bnot $mask)
            
            # Check overlap with provided ranges
            $hasOverlap = $false
            $fullyContained = $false
            
            foreach ($range in $ConvertedRanges) {
                if (Test-RangeContains -ContainerStart $range.Start -ContainerEnd $range.End -InnerStart $networkInt -InnerEnd $broadcastInt) {
                    $fullyContained = $true
                    break
                }
                
                if (Test-RangeOverlap -Range1Start $networkInt -Range1End $broadcastInt -Range2Start $range.Start -Range2End $range.End) {
                    $hasOverlap = $true
                }
            }
            
            if ($fullyContained) {
                return "Yes"
            }
            elseif ($hasOverlap) {
                return "Partial"
            }
            else {
                return "No"
            }
        }
        
        # Check if it's a range
        $rangePattern = "^(?<start>$((Get-IPRegex -IPv4)))\s*-\s*(?<end>$((Get-IPRegex -IPv4)))$"
        if ($input -match $rangePattern) {
            $startIP = $matches['start']
            $endIP = $matches['end']
            
            # Validate IP addresses
            [IPAddress]$startIPObj = $null
            [IPAddress]$endIPObj = $null
            
            if (-not [System.Net.IPAddress]::TryParse($startIP, [ref]$startIPObj)) {
                Write-Error "Start IP address '$startIP' is not valid."
                return "No"
            }
            
            if (-not [System.Net.IPAddress]::TryParse($endIP, [ref]$endIPObj)) {
                Write-Error "End IP address '$endIP' is not valid."
                return "No"
            }
            
            $startIPInt = ConvertTo-IPUInt32 -IP $startIPObj
            $endIPInt = ConvertTo-IPUInt32 -IP $endIPObj
            
            if ($startIPInt -gt $endIPInt) {
                Write-Error "Start IP address is greater than end IP address."
                return "No"
            }
            
            # Check overlap with provided ranges
            $hasOverlap = $false
            $fullyContained = $false
            
            foreach ($range in $ConvertedRanges) {
                if (Test-RangeContains -ContainerStart $range.Start -ContainerEnd $range.End -InnerStart $startIPInt -InnerEnd $endIPInt) {
                    $fullyContained = $true
                    break
                }
                
                if (Test-RangeOverlap -Range1Start $startIPInt -Range1End $endIPInt -Range2Start $range.Start -Range2End $range.End) {
                    $hasOverlap = $true
                }
            }
            
            if ($fullyContained) {
                return "Yes"
            }
            elseif ($hasOverlap) {
                return "Partial"
            }
            else {
                return "No"
            }
        }
        
        # Check if it's a single IP
        $ipRegex = Get-IPRegex -IPv4 -FullLine
        if ($input -match $ipRegex) {
            [IPAddress]$ip = $null
            if (-not [System.Net.IPAddress]::TryParse($input, [ref]$ip)) {
                Write-Error "IP address '$input' is not valid."
                return "No"
            }
            
            # Check if the IP address is IPv4
            if ($ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
                Write-Warning "Address '$input' is not an IPv4."
                return "No"
            }
            
            $octets = $ip.GetAddressBytes()
            
            if (Test-OctetsInRange -octets $octets -ranges $Ranges) {
                return "Yes"
            }
            else {
                return "No"
            }
        }
        
        # Check if it's a DNS name (only after all IP formats have been tested)
        $dnsRegex = Get-DNSRegex -FullLine
        if ($input -match $dnsRegex) {
            try {
                # Resolve DNS name to IP addresses
                $resolvedIPs = [System.Net.Dns]::GetHostAddresses($input) | Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork }
                
                if ($resolvedIPs.Count -eq 0) {
                    Write-Warning "DNS name '$input' did not resolve to any IPv4 addresses."
                    return "No"
                }
                
                # Check if all resolved IPs are in range
                $allInRange = $true
                $anyInRange = $false
                
                foreach ($resolvedIP in $resolvedIPs) {
                    $octets = $resolvedIP.GetAddressBytes()
                    $isInRange = Test-OctetsInRange -octets $octets -ranges $Ranges
                    
                    if ($isInRange) {
                        $anyInRange = $true
                    }
                    else {
                        $allInRange = $false
                    }
                }
                
                if ($allInRange) {
                    return "Yes"
                }
                elseif ($anyInRange) {
                    return "Partial"
                }
                else {
                    return "No"
                }
            }
            catch {
                Write-Error "Failed to resolve DNS name '$input': $_"
                return "No"
            }
        }
        
        # Unrecognized format
        Write-Error "Format of '$input' is not recognized. Accepted formats: IP (192.168.1.1), DNS name (server.domain.com), CIDR network (192.168.1.0/24), Range (192.168.1.1-192.168.1.254)"
        return "No"
    }
}
