function Test-IsPrivateIP {
    <#
    .SYNOPSIS
        Checks if an IP address, network or range belongs to private/internal IP ranges.
    
    .DESCRIPTION
        This function determines if an IP address, CIDR network or IP range belongs to the
        private IP address ranges that are not routed on the Internet:
        - 10.0.0.0/8     (10.0.0.0 - 10.255.255.255)         - RFC1918
        - 172.16.0.0/12  (172.16.0.0 - 172.31.255.255)       - RFC1918
        - 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)     - RFC1918
        - 100.64.0.0/10  (100.64.0.0 - 100.127.255.255)      - RFC6598 (Carrier-Grade NAT)
        
        Returns:
        - "Yes" : If the entire input is within private ranges
        - "No" : If the entire input is outside private ranges
        - "Partial" : If only part of the range is within private ranges
    
    .PARAMETER IPAddress
        The IP address, CIDR network or range to check as a string.
        Accepted formats:
        - Single IP: "192.168.1.1"
        - CIDR network: "192.168.1.0/24"
        - Range: "192.168.1.1-192.168.1.254"
    
    .EXAMPLE
        Test-IsPrivateIP -IPAddress "10.0.0.1"
        # Returns: Yes
    
    .EXAMPLE
        Test-IsPrivateIP -IPAddress "100.64.0.1"
        # Returns: Yes (RFC6598 - Carrier-Grade NAT)
    
    .EXAMPLE
        Test-IsPrivateIP -IPAddress "192.168.1.0/24"
        # Returns: Yes
    
    .EXAMPLE
        Test-IsPrivateIP -IPAddress "8.8.8.0/24"
        # Returns: No

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [string]$IPAddress
    )
    
    Process {
        $PrivateRanges = @(
            @{ Name = "10.0.0.0/8";     Start = "10.0.0.0";     End = "10.255.255.255" },
            @{ Name = "172.16.0.0/12";  Start = "172.16.0.0";   End = "172.31.255.255" },
            @{ Name = "192.168.0.0/16"; Start = "192.168.0.0";  End = "192.168.255.255" },
            @{ Name = "100.64.0.0/10";  Start = "100.64.0.0";   End = "100.127.255.255" }
        )
        
        Test-IPInRange -IPAddress $IPAddress -Ranges $PrivateRanges
    }
}