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
        Version : 1.0.0
    #>
    $sForestName = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().Name 
    $oForest = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$sForestName")
    $oResult = $oForest | ConvertTo-ADObject
    $oResult.AdditionalProperties.ForestName = $sForestName
    return $oResult
}