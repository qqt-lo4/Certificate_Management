function Get-NetScalerContentSwitchHostname {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [object]$Session,
        [Parameter(Mandatory)]
        [string]$VirtualServer
    )

    try {
        $oBindingResponse = Invoke-NetScalerNitroApi -Session $Session `
            -Resource 'csvserver_cspolicy_binding' -Identifier $VirtualServer
    } catch {
        Write-Verbose "No Content Switching policy bindings returned for '$VirtualServer': $_"
        return @()
    }

    $hHostNames = @{}
    foreach ($oBinding in @($oBindingResponse.csvserver_cspolicy_binding)) {
        if (-not $oBinding.policyname) { continue }
        try {
            $oPolicyResponse = Invoke-NetScalerNitroApi -Session $Session `
                -Resource 'cspolicy' -Identifier ([string]$oBinding.policyname)
            foreach ($oPolicy in @($oPolicyResponse.cspolicy)) {
                $sHostPattern = '(?i)HTTP\.REQ\.HOSTNAME\s*\.\s*EQ\s*\(\s*["'']([^"'']+)["'']\s*\)'
                foreach ($oMatch in [regex]::Matches([string]$oPolicy.rule, $sHostPattern)) {
                    $sHostName = $oMatch.Groups[1].Value.Trim().TrimEnd('.')
                    if ($sHostName -and $sHostName -notmatch '\*') {
                        $hHostNames[$sHostName.ToLowerInvariant()] = [PSCustomObject]@{
                            HostName = $sHostName
                            CertificateKey = $null
                            DiscoverySource = "CS policy: $($oPolicy.name)"
                        }
                    }
                }
            }
        } catch {
            Write-Verbose "Could not inspect Content Switching policy '$($oBinding.policyname)': $_"
        }
    }

    return @($hHostNames.Values)
}