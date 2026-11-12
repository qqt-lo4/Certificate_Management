function Get-NetScalerSSLVirtualServer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [object]$Session
    )

    foreach ($sResource in @('lbvserver', 'csvserver')) {
        try {
            $oResponse = Invoke-NetScalerNitroApi -Session $Session -Resource $sResource `
                -Query @{ attrs = 'name,ipv46,port,servicetype,curstate' }
        } catch {
            Write-Warning "Could not enumerate NetScaler resource '$sResource': $_"
            continue
        }

        foreach ($oVServer in @($oResponse.$sResource)) {
            if ($oVServer.servicetype -notin @('SSL', 'SSL_TCP')) { continue }
            [PSCustomObject]@{
                Name = [string]$oVServer.name
                Type = $sResource
                VIP = [string]$oVServer.ipv46
                Port = [int]$oVServer.port
                ServiceType = [string]$oVServer.servicetype
                State = [string]$oVServer.curstate
            }
        }
    }
}