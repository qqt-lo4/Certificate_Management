function Resolve-ProxyPAC {
    <#
    .SYNOPSIS
        Resolves a proxy PAC file for a given URL

    .DESCRIPTION
        Uses the Windows WinHTTP API to evaluate a PAC (Proxy Auto-Configuration)
        file and determine the appropriate proxy for a specific URL. Supports
        auto-detection, system PAC URL, custom PAC URL, or inline PAC content.

    .PARAMETER Url
        The destination URL to resolve the proxy for.

    .PARAMETER PacUrl
        The URL of the PAC file to use (optional, defaults to system configuration).

    .PARAMETER PacContent
        The PAC file content as a string (optional, alternative to PacUrl).

    .OUTPUTS
        [PSCustomObject]. Proxy resolution result with ProxyString, ProxyList, Method, Success.

    .EXAMPLE
        Resolve-ProxyPAC -Url "http://www.google.com"

    .EXAMPLE
        Resolve-ProxyPAC -Url "http://www.google.com" -PacUrl "http://proxy.company.com/proxy.pac"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        
        [Parameter(Mandatory = $false)]
        [string]$PacUrl,
        
        [Parameter(Mandatory = $false)]
        [string]$PacContent
    )
    
    try {
        # Add required .NET types for WinHTTP
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public class WinHttpPac
{
    [DllImport("winhttp.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr WinHttpOpen(
        string pwszUserAgent,
        int dwAccessType,
        string pwszProxyName,
        string pwszProxyBypass,
        int dwFlags);

    [DllImport("winhttp.dll", CharSet = CharSet.Unicode)]
    public static extern bool WinHttpGetProxyForUrl(
        IntPtr hSession,
        string lpcwszUrl,
        ref WINHTTP_AUTOPROXY_OPTIONS pAutoProxyOptions,
        out WINHTTP_PROXY_INFO pProxyInfo);

    [DllImport("winhttp.dll")]
    public static extern bool WinHttpCloseHandle(IntPtr hInternet);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WINHTTP_AUTOPROXY_OPTIONS
    {
        public int dwFlags;
        public int dwAutoDetectFlags;
        public string lpszAutoConfigUrl;
        public IntPtr lpvReserved;
        public int dwReserved;
        public bool fAutoLogonIfChallenged;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WINHTTP_PROXY_INFO
    {
        public int dwAccessType;
        public string lpszProxy;
        public string lpszProxyBypass;
    }

    // Constants
    public const int WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0;
    public const int WINHTTP_AUTOPROXY_AUTO_DETECT = 0x00000001;
    public const int WINHTTP_AUTOPROXY_CONFIG_URL = 0x00000002;
    public const int WINHTTP_AUTO_DETECT_TYPE_DHCP = 0x00000001;
    public const int WINHTTP_AUTO_DETECT_TYPE_DNS_A = 0x00000002;
}
"@

        # Initialize the result
        $ProxyResult = [PSCustomObject]@{
            Url = $Url
            PacUrl = $PacUrl
            ProxyString = $null
            ProxyList = @()
            Method = $null
            Success = $false
            ErrorMessage = $null
            Timestamp = Get-Date
        }

        # Determine the method to use
        if ($PacContent) {
            # Alternative method with provided PAC content
            $ProxyResult = Resolve-ProxyPACContent -Url $Url -PacContent $PacContent
            return $ProxyResult
        }
        
        # Open a WinHTTP session
        $hSession = [WinHttpPac]::WinHttpOpen(
            "PowerShell PAC Resolver", 
            [WinHttpPac]::WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, 
            $null, 
            $null, 
            0
        )
        
        if ($hSession -eq [IntPtr]::Zero) {
            throw "Unable to open a WinHTTP session"
        }
        
        try {
            # Configure automatic proxy options
            $autoProxyOptions = New-Object WinHttpPac+WINHTTP_AUTOPROXY_OPTIONS
            
            if ($PacUrl) {
                # Use a specific PAC file
                $autoProxyOptions.dwFlags = [WinHttpPac]::WINHTTP_AUTOPROXY_CONFIG_URL
                $autoProxyOptions.lpszAutoConfigUrl = $PacUrl
                $ProxyResult.Method = "PAC URL from parameters"
                $ProxyResult.PacUrl = $PacUrl
            }
            else {
                # Auto-detect or use system configuration
                $userProxy = Get-UserProxy
                if ($userProxy.AutoConfigURL) {
                    $autoProxyOptions.dwFlags = [WinHttpPac]::WINHTTP_AUTOPROXY_CONFIG_URL
                    $autoProxyOptions.lpszAutoConfigUrl = $userProxy.AutoConfigURL
                    $ProxyResult.Method = "PAC URL from user"
                    $ProxyResult.PacUrl = $userProxy.AutoConfigURL
                }
                else {
                    $autoProxyOptions.dwFlags = [WinHttpPac]::WINHTTP_AUTOPROXY_AUTO_DETECT
                    $autoProxyOptions.dwAutoDetectFlags = [WinHttpPac]::WINHTTP_AUTO_DETECT_TYPE_DHCP -bor [WinHttpPac]::WINHTTP_AUTO_DETECT_TYPE_DNS_A
                    $ProxyResult.Method = "Auto-detect"
                }
            }
            
            $autoProxyOptions.fAutoLogonIfChallenged = $true
            
            # Call the API to resolve the proxy
            $proxyInfo = New-Object WinHttpPac+WINHTTP_PROXY_INFO
            $success = [WinHttpPac]::WinHttpGetProxyForUrl($hSession, $Url, [ref]$autoProxyOptions, [ref]$proxyInfo)
            
            if ($success) {
                $ProxyResult.Success = $true
                $ProxyResult.ProxyString = $proxyInfo.lpszProxy
                
                # Parse the returned proxy string
                if ($proxyInfo.lpszProxy) {
                    $proxies = $proxyInfo.lpszProxy -split ';' | ForEach-Object { $_.Trim() }
                    $ProxyResult.ProxyList = $proxies | Where-Object { $_ -ne '' } | ForEach-Object {
                        if ($_ -eq "DIRECT") {
                            [PSCustomObject]@{ Type = "DIRECT"; Server = $null; Port = $null }
                        }
                        elseif ($_ -match '^(PROXY|HTTP|HTTPS|SOCKS|SOCKS4|SOCKS5)\s+(.+):(\d+)$') {
                            [PSCustomObject]@{ Type = $matches[1]; Server = $matches[2]; Port = [int]$matches[3] }
                        }
                        elseif ($_ -match '^(.+):(\d+)$') {
                            [PSCustomObject]@{ Type = "PROXY"; Server = $matches[1]; Port = [int]$matches[2] }
                        }
                        else {
                            [PSCustomObject]@{ Type = "UNKNOWN"; Server = $_; Port = $null }
                        }
                    }
                }
            }
            else {
                $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                throw "WinHttpGetProxyForUrl failed with error code: $errorCode"
            }
        }
        finally {
            # Close the WinHTTP session
            [WinHttpPac]::WinHttpCloseHandle($hSession) | Out-Null
        }
        
        # Display results
        Write-Host "`n=== Proxy PAC Resolution ===" -ForegroundColor Green
        Write-Host "Target URL: $($ProxyResult.Url)" -ForegroundColor Yellow
        Write-Host "Method: $($ProxyResult.Method)" -ForegroundColor Cyan
        if ($ProxyResult.PacUrl) {
            Write-Host "PAC file: $($ProxyResult.PacUrl)" -ForegroundColor Cyan
        }
        Write-Host "Success: $($ProxyResult.Success)" -ForegroundColor $(if($ProxyResult.Success){'Green'}else{'Red'})
        
        if ($ProxyResult.Success) {
            Write-Host "Raw proxy string: $($ProxyResult.ProxyString)" -ForegroundColor White
            Write-Host "Detected proxies:" -ForegroundColor Cyan
            foreach ($proxy in $ProxyResult.ProxyList) {
                if ($proxy.Type -eq "DIRECT") {
                    Write-Host "  - Direct connection (no proxy)" -ForegroundColor Green
                }
                else {
                    Write-Host "  - $($proxy.Type): $($proxy.Server):$($proxy.Port)" -ForegroundColor White
                }
            }
        }
        else {
            Write-Host "Error: $($ProxyResult.ErrorMessage)" -ForegroundColor Red
        }
        
        return $ProxyResult
    }
    catch {
        $ProxyResult.Success = $false
        $ProxyResult.ErrorMessage = $_.Exception.Message
        Write-Error "Error during PAC resolution: $($_.Exception.Message)"
        return $ProxyResult
    }
}
