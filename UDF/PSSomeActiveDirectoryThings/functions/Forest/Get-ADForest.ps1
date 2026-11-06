function Get-ADForest {
    <#
    .SYNOPSIS
        Returns the current AD forest as a converted AD object

    .DESCRIPTION
        Retrieves the current forest root domain entry via LDAP, converts it
        to a custom AD object, and adds the ForestName as an additional property.

    .OUTPUTS
        Custom AD object with forest properties and ForestName.

    .EXAMPLE
        $forest = Get-ADForest

    .NOTES
        Author  : Loïc Ade
        Version : 1.1.0

        CHANGELOG:

        Version 1.1.0 - 2026-10-25 - Loïc Ade
            - Fallbacks when GetCurrentForest fails ("Current security context is not associated
              with an Active Directory domain or forest"): forest of the computer domain, then
              USERDNSDOMAIN. A warning shows the original error.

        Version 1.0.0 - Loïc Ade
            - Initial release
    #>
    $sForestName = $null
    try {
        $sForestName = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name
    } catch {
        $sError = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { $_.Exception.Message }
        try {
            $sForestName = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Forest.Name
            Write-Warning "Current forest lookup failed ($sError). Using the computer's forest: $sForestName"
        } catch {
            if ($env:USERDNSDOMAIN) {
                $sForestName = $env:USERDNSDOMAIN.ToLower()
                Write-Warning "Current forest lookup failed ($sError). Using USERDNSDOMAIN: $sForestName"
            } else {
                throw "Unable to find the Active Directory forest: $sError"
            }
        }
    }
    $oForest = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$sForestName")
    $oResult = $oForest | ConvertTo-ADObject
    $oResult.AdditionalProperties.ForestName = $sForestName
    return $oResult
}