function Test-IsRFC1918 {
    <#
    .SYNOPSIS
        Checks if an IP address, network or range belongs to RFC1918 ranges (private IP addresses).
    
    .DESCRIPTION
        This function determines if an IP address, CIDR network or IP range belongs to the
        private IP address ranges defined in RFC1918:
        - 10.0.0.0/8     (10.0.0.0 - 10.255.255.255)
        - 172.16.0.0/12  (172.16.0.0 - 172.31.255.255)
        - 192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
        
        Returns:
        - "Yes" : If the entire input is within RFC1918 ranges
        - "No" : If the entire input is outside RFC1918 ranges
        - "Partial" : If only part of the range is within RFC1918
    
    .PARAMETER IPAddress
        The IP address, CIDR network or range to check as a string.
        Accepted formats:
        - Single IP: "192.168.1.1"
        - CIDR network: "192.168.1.0/24"
        - Range: "192.168.1.1-192.168.1.254"
    
    .EXAMPLE
        Test-IsRFC1918 -IPAddress "10.0.0.1"
        # Returns: Yes
    
    .EXAMPLE
        Test-IsRFC1918 -IPAddress "192.168.1.0/24"
        # Returns: Yes
    
    .EXAMPLE
        Test-IsRFC1918 -IPAddress "8.8.8.0/24"
        # Returns: No
    
    .EXAMPLE
        Test-IsRFC1918 -IPAddress "100.64.0.1"
        # Returns: No (RFC6598, not RFC1918)

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
        $RFC1918Ranges = @(
            @{ Name = "10.0.0.0/8";     Start = "10.0.0.0";     End = "10.255.255.255" },
            @{ Name = "172.16.0.0/12";  Start = "172.16.0.0";   End = "172.31.255.255" },
            @{ Name = "192.168.0.0/16"; Start = "192.168.0.0";  End = "192.168.255.255" }
        )
        
        Test-IPInRange -IPAddress $IPAddress -Ranges $RFC1918Ranges
    }
}
