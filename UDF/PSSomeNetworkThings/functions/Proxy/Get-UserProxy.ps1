function Get-UserProxy {
    <#
    .SYNOPSIS
        Gets the current user's proxy configuration

    .DESCRIPTION
        Retrieves proxy settings from Internet Explorer/Edge registry keys
        for the current user, including auto-config URL (PAC), manual proxy,
        bypass list, and auto-detect settings.

    .OUTPUTS
        [PSCustomObject]. Proxy configuration with ProxyEnabled, ProxyServer, ProxyOverride, AutoConfigURL, AutoDetect.

    .EXAMPLE
        Get-UserProxy

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    
    [CmdletBinding()]
    param()
    
    try {
        # Registry key for Internet Explorer/Edge settings
        $ProxyRegPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        
        # Initialize the result object
        $ProxyConfig = [PSCustomObject]@{
            ProxyEnabled = $false
            ProxyServer = $null
            ProxyOverride = $null
            AutoConfigURL = $null
            AutoDetect = $false
            ProxySettingsPerUser = $true
            Timestamp = Get-Date
        }
        
        # Check if the registry key exists
        if (Test-Path $ProxyRegPath) {
            $ProxySettings = Get-ItemProperty -Path $ProxyRegPath -ErrorAction SilentlyContinue
            
            if ($ProxySettings) {
                # Manual proxy enabled
                $ProxyConfig.ProxyEnabled = [bool]$ProxySettings.ProxyEnable
                
                # Proxy server
                if ($ProxySettings.ProxyServer) {
                    $ProxyConfig.ProxyServer = $ProxySettings.ProxyServer
                }
                
                # Proxy exceptions (sites that bypass the proxy)
                if ($ProxySettings.ProxyOverride) {
                    $ProxyConfig.ProxyOverride = $ProxySettings.ProxyOverride
                }
                
                # Automatic configuration URL (PAC)
                if ($ProxySettings.AutoConfigURL) {
                    $ProxyConfig.AutoConfigURL = $ProxySettings.AutoConfigURL
                }
                
                # Automatic settings detection
                $ProxyConfig.AutoDetect = [bool]$ProxySettings.AutoDetect
                
                # Check if settings are per-user or system-wide
                $ProxyConfig.ProxySettingsPerUser = [bool]$ProxySettings.ProxySettingsPerUser
            }
        }
        
        return $ProxyConfig
        
    }
    catch {
        Write-Error "Error retrieving proxy configuration: $($_.Exception.Message)"
        return $null
    }
}