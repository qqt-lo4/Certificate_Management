function Get-SystemProxyConfiguration {
    <#
    .SYNOPSIS
        Gets the system-level proxy configuration (WinHTTP)

    .DESCRIPTION
        Retrieves the WinHTTP proxy configuration by parsing the output of
        "netsh winhttp dump proxy". Returns proxy server, bypass list, and status.

    .OUTPUTS
        [PSCustomObject]. Proxy configuration with ProxyEnabled, ProxyServer, ProxyBypass, ConfigSource, RawOutput, Timestamp.

    .EXAMPLE
        Get-SystemProxyConfiguration

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    
    try {
        # Initialize the result object
        $SystemProxyConfig = [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            ProxyEnabled = $false
            ProxyServer = $null
            ProxyBypass = $null
            ConfigSource = "WinHTTP"
            RawOutput = $null
            Timestamp = Get-Date
        }
        
        # Execute netsh winhttp dump proxy
        $WinHttpDump = netsh winhttp dump proxy 2>$null
        $SystemProxyConfig.RawOutput = $WinHttpDump
        
        if ($WinHttpDump) {
            foreach ($line in $WinHttpDump) {
                # Regex to parse the "set proxy proxy-server=..." line
                if ($line -match '^set proxy proxy-server="([^"]*)"(?:\s+bypass-list="([^"]*)")?') {
                    $SystemProxyConfig.ProxyEnabled = $true
                    $SystemProxyConfig.ProxyServer = $matches[1]
                    
                    # Retrieve the bypass-list if present
                    if ($matches[2]) {
                        $SystemProxyConfig.ProxyBypass = $matches[2]
                    }
                }
                # Check if proxy is disabled
                elseif ($line -match 'set proxy proxy-server="direct"') {
                    $SystemProxyConfig.ProxyEnabled = $false
                    $SystemProxyConfig.ProxyServer = "direct"
                }
            }
        }
        
        return $SystemProxyConfig
    }
    catch {
        Write-Error "Error retrieving WinHTTP configuration: $($_.Exception.Message)"
        return $null
    }
}