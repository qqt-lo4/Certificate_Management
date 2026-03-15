function Set-InternetProxy
{
    <#
    .SYNOPSIS
        Sets the Internet proxy configuration for the current user

    .DESCRIPTION
        Configures the proxy settings in the Windows registry (Internet Settings).
        Can set a manual proxy server with bypass list, an auto-config script (PAC),
        or disable the proxy entirely when called without parameters.

    .PARAMETER Proxy
        The proxy server address (e.g. "proxy.domain.com:8080").

    .PARAMETER ProxyOverride
        Semicolon-separated list of addresses that bypass the proxy (default: "<local>").

    .PARAMETER AutoConfigScript
        URL of a PAC auto-configuration script.

    .EXAMPLE
        Set-InternetProxy -Proxy "proxy.domain.com:8080"

    .EXAMPLE
        Set-InternetProxy

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

    [CmdletBinding()]
    Param(        
        [Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$Proxy,

        [Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [string]$ProxyOverride = "<local>",

        [Parameter(Mandatory=$False,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [AllowEmptyString()]
        [string]$AutoConfigScript                
    )

    Begin {
        $regKey="HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"        
    }
    
    Process {        
        if ($Proxy -or $AutoConfigScript) {
            if ($Proxy) {
                Set-ItemProperty -path $regKey ProxyEnable -value 1
                Set-ItemProperty -path $regKey -name ProxyServer -value $Proxy
                Set-ItemProperty -path $regKey -name ProxyOverride -value $ProxyOverride
            }
            if ($AutoConfigScript) {
                Set-ItemProperty -path $regKey -name AutoConfigURL -Value $AutoConfigScript
            }    
        } else {
            Set-ItemProperty -path $regKey -name ProxyEnable -value 0
            Set-ItemProperty -path $regKey -name AutoConfigURL -Value ""
            Set-ItemProperty -Path $regKey -name ProxyServer -Value ""
        }
    } 
    
    End {}
}
