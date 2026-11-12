function Connect-NetScalerNitroSession {
    [CmdletBinding(DefaultParameterSetName = 'ManagementUri')]
    Param(
        [Parameter(Mandatory, ParameterSetName = 'ManagementUri')]
        [uri]$ManagementUri,

        [Parameter(Mandatory, ParameterSetName = 'HostPort')]
        [ValidateNotNullOrEmpty()]
        [string]$HostName,

        [Parameter(ParameterSetName = 'HostPort')]
        [ValidateRange(1, 65535)]
        [int]$Port = 443,

        [Parameter(Mandatory)]
        [PSCredential]$Credential,
        [ValidateRange(1, 120)]
        [int]$TimeoutSeconds = 15
    )

    if ($PSCmdlet.ParameterSetName -eq 'HostPort') {
        if ([System.Uri]::CheckHostName($HostName) -eq [System.UriHostNameType]::Unknown) {
            throw "Invalid NetScaler host name: '$HostName'."
        }
        $oUriBuilder = New-Object System.UriBuilder('https', $HostName, $Port)
        $ManagementUri = $oUriBuilder.Uri
    }

    if ($ManagementUri.Scheme -ne 'https' -or $ManagementUri.UserInfo -or $ManagementUri.Query -or $ManagementUri.Fragment) {
        throw 'ManagementUri must be an HTTPS URI without embedded credentials, query, or fragment.'
    }

    $sBaseUri = $ManagementUri.GetLeftPart([System.UriPartial]::Authority).TrimEnd('/')
    $oWebSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $pPassword = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)
    try {
        $sPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($pPassword)
        $hLogin = @{
            login = @{
                username = $Credential.UserName
                password = $sPassword
            }
        }
        $oResponse = Invoke-RestMethod -Uri "$sBaseUri/nitro/v1/config/login" -Method Post `
            -WebSession $oWebSession -TimeoutSec $TimeoutSeconds -UseBasicParsing `
            -ContentType 'application/json' -Body ($hLogin | ConvertTo-Json -Compress) -ErrorAction Stop
        if ($null -ne $oResponse.errorcode -and [int]$oResponse.errorcode -ne 0) {
            throw "Nitro login failed ($($oResponse.errorcode)): $($oResponse.message)"
        }
    } catch {
        $oWebSession.Cookies.GetCookies($ManagementUri) | ForEach-Object { $_.Expired = $true }
        throw "Could not authenticate to NetScaler Nitro API at '$sBaseUri': $_"
    } finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pPassword)
    }

    return [PSCustomObject]@{
        ManagementUri = $sBaseUri
        WebSession = $oWebSession
        TimeoutSeconds = $TimeoutSeconds
    }
}