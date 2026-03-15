function Test-PrivateOrDocumentedIP {
    <#
    .SYNOPSIS
        Tests if an IP address belongs to a private or documented range

    .DESCRIPTION
        Checks whether an IPv4 or IPv6 address belongs to a private, reserved,
        or documentation range (RFC 1918, RFC 6598, RFC 5737, link-local,
        loopback, multicast, etc.) that should not be queried via public RDAP.

    .PARAMETER IPAddress
        The IP address to check (IPv4 or IPv6).

    .OUTPUTS
        [Hashtable]. Contains IsPrivateOrDocumented (bool), Range, Description, and IPVersion.

    .EXAMPLE
        Test-PrivateOrDocumentedIP -IPAddress "192.168.1.1"
        # IsPrivateOrDocumented = $true, Range = "192.168.0.0/16"

    .EXAMPLE
        Test-PrivateOrDocumentedIP -IPAddress "8.8.8.8"
        # IsPrivateOrDocumented = $false, Description = "Public IP"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$IPAddress
    )
    
    # Define IP ranges that should not be queried via RDAP
    $PrivateRanges = @{
        # RFC 1918 - Private Address Space
        "10.0.0.0/8" = "Private (RFC 1918)"
        "172.16.0.0/12" = "Private (RFC 1918)" 
        "192.168.0.0/16" = "Private (RFC 1918)"
        
        # RFC 3927 - Link-Local (APIPA)
        "169.254.0.0/16" = "Link-Local (RFC 3927)"
        
        # RFC 5735/RFC 6890 - Special Use IPv4
        "127.0.0.0/8" = "Loopback (RFC 5735)"
        "0.0.0.0/8" = "This Network (RFC 5735)"
        "224.0.0.0/4" = "Multicast (RFC 5735)"
        "240.0.0.0/4" = "Reserved (RFC 5735)"
        "255.255.255.255/32" = "Broadcast (RFC 5735)"
        
        # RFC 5737 - Documentation ranges
        "192.0.2.0/24" = "Documentation (RFC 5737)"
        "198.51.100.0/24" = "Documentation (RFC 5737)"
        "203.0.113.0/24" = "Documentation (RFC 5737)"
        
        # RFC 1122 - Special addresses
        "0.0.0.0/32" = "Default Route (RFC 1122)"
        
        # RFC 3068 - 6to4 relay anycast
        "192.88.99.0/24" = "6to4 Relay (RFC 3068)"
        
        # RFC 2544 - Benchmarking
        "198.18.0.0/15" = "Benchmarking (RFC 2544)"
        
        # RFC 6598 - Carrier Grade NAT
        "100.64.0.0/10" = "Carrier Grade NAT (RFC 6598)"
    }
    
    $IPv6PrivateRanges = @{
        # RFC 4193 - Unique Local Addresses
        "fc00::/7" = "Unique Local (RFC 4193)"
        
        # RFC 4291 - IPv6 Addressing Architecture
        "::1/128" = "Loopback (RFC 4291)"
        "::/128" = "Unspecified (RFC 4291)"
        "fe80::/10" = "Link-Local (RFC 4291)"
        "ff00::/8" = "Multicast (RFC 4291)"
        
        # RFC 3849 - Documentation
        "2001:db8::/32" = "Documentation (RFC 3849)"
        
        # RFC 2526 - 6bone (deprecated)
        "3ffe::/16" = "6bone (RFC 2526 - deprecated)"
        
        # RFC 4380 - Teredo
        "2001::/32" = "Teredo (RFC 4380)"
        
        # RFC 3964 - 6to4
        "2002::/16" = "6to4 (RFC 3964)"
        
        # RFC 4843 - ORCHID
        "2001:10::/28" = "ORCHID (RFC 4843)"
        
        # RFC 6052 - Well-Known Prefix
        "64:ff9b::/96" = "Well-Known Prefix (RFC 6052)"
    }
    
    # Detect if it's IPv4 or IPv6
    $ipv4Regex = Get-IPRegex -IPv4 -FullLine
    $ipv6Regex = Get-IPRegex -IPv6 -FullLine
    
    try {
        if ($IPAddress -match $ipv4Regex) {
            # Check IPv4 ranges with Test-IPInNetwork function
            foreach ($range in $PrivateRanges.Keys) {
                $networkParts = $range -split '/'
                $networkIP = $networkParts[0]
                $mask = $networkParts[1]
                
                if (Test-IPInNetwork -IPAddress ([IPAddress]$IPAddress) -Network $networkIP -SubnetMask $mask) {
                    return @{
                        IsPrivateOrDocumented = $true
                        Range = $range
                        Description = $PrivateRanges[$range]
                        IPVersion = "IPv4"
                    }
                }
            }
        }
        elseif ($IPAddress -match $ipv6Regex) {
            # Check IPv6 ranges with Test-IPv6InNetwork function
            foreach ($range in $IPv6PrivateRanges.Keys) {
                if (Test-IPv6InNetwork -IPAddress $IPAddress -Network $range) {
                    return @{
                        IsPrivateOrDocumented = $true
                        Range = $range
                        Description = $IPv6PrivateRanges[$range]
                        IPVersion = "IPv6"
                    }
                }
            }
        }
    }
    catch {
        Write-Verbose "Error checking IP '$IPAddress': $($_.Exception.Message)"
        # In case of error, consider as public for safety
    }
    
    # Public IP
    return @{
        IsPrivateOrDocumented = $false
        Range = $null
        Description = "Public IP"
        IPVersion = if ($IPAddress -match $ipv4Regex) { "IPv4" } else { "IPv6" }
    }
}