function Invoke-NetScalerNitroApi {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [object]$Session,
        [Parameter(Mandatory)]
        [string]$Resource,
        [string]$Identifier,
        [System.Collections.IDictionary]$Query,
        [ValidateSet('GET', 'POST')]
        [string]$Method = 'GET',
        [object]$Body
    )

    $sPath = $Resource.Trim('/')
    if ($Identifier) { $sPath += '/' + [Uri]::EscapeDataString($Identifier) }
    if ($Query -and $Query.Count -gt 0) {
        $aQueryItems = foreach ($sKey in $Query.Keys) {
            '{0}={1}' -f [Uri]::EscapeDataString([string]$sKey), [Uri]::EscapeDataString([string]$Query[$sKey])
        }
        $sPath += '?' + ($aQueryItems -join '&')
    }

    $hParams = @{
        Uri = "$($Session.ManagementUri)/nitro/v1/config/$sPath"
        Method = $Method
        WebSession = $Session.WebSession
        TimeoutSec = $Session.TimeoutSeconds
        UseBasicParsing = $true
        ErrorAction = 'Stop'
    }
    if ($null -ne $Body) {
        $hParams.ContentType = 'application/json'
        $hParams.Body = $Body | ConvertTo-Json -Depth 10 -Compress
    }

    $oResponse = Invoke-RestMethod @hParams
    if ($null -ne $oResponse.errorcode -and [int]$oResponse.errorcode -ne 0) {
        throw "Nitro request '$sPath' failed ($($oResponse.errorcode)): $($oResponse.message)"
    }
    return $oResponse
}