function Disconnect-NetScalerNitroSession {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [object]$Session
    )

    try {
        Invoke-NetScalerNitroApi -Session $Session -Resource 'logout' -Method POST -Body @{ logout = @{} } | Out-Null
    } catch {
        Write-Verbose "NetScaler Nitro logout failed: $_"
    } finally {
        if ($Session.WebSession -and $Session.WebSession.Cookies) {
            $Session.WebSession.Cookies.GetCookies([uri]$Session.ManagementUri) | ForEach-Object { $_.Expired = $true }
        }
    }
}