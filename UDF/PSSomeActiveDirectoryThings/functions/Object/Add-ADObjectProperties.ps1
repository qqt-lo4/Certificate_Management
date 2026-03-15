function Add-ADObjectProperties {
    <#
    .SYNOPSIS
        Loads additional properties onto existing AD objects

    .DESCRIPTION
        Queries AD to add missing properties to existing AD objects. Supports
        string property names and hashtable-based calculated properties (extracting
        the required AD attribute from the expression scriptblock).

    .PARAMETER ADObject
        The AD object(s) to enrich. Accepts pipeline input.

    .PARAMETER Properties
        Property names (strings) or calculated property hashtables to load.

    .PARAMETER Credential
        Optional PSCredential for AD authentication.

    .OUTPUTS
        The enriched AD object(s).

    .EXAMPLE
        $user | Add-ADObjectProperties -Properties "mail","department"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [object[]]$ADObject,
        [Parameter(Mandatory, Position = 1)]
        [object[]]$Properties,
        [Parameter(Position = 2)]
        [pscredential]$Credential
    )
    Begin {
        $aNewProperties = @()
        foreach ($p in $Properties) {
            if ($p -is [string]) {
                $aNewProperties += $p
            } elseif ($p -is [hashtable]) {
                $sbExpression = if ($p["e"]) { $p["e"] } elseif ($p["E"]) { $p["E"]} else { $p["expression"] }
                $sProperty = $sbExpression.ToString().Trim() 
                $sProperty = $sProperty | Select-String -Pattern "^\`$_`.`"?(?<property>[^.`"]+)"
                $sProperty = $sProperty.Matches.Groups 
                $sProperty = $sProperty | Where-Object { $_.Name -eq "property" }
                if ($null -ne $sProperty) {
                    $aNewProperties += $sProperty.Value
                }
            }
        }
        $aADObject = @()
    }
    Process {
        $aADObject += $ADObject
    } 
    End {
        foreach ($ado in $aADObject) {
            if ($ado.AdditionalProperties.SearchResult) {
                $hGetADObject = @{
                    Path = $ado.AdditionalProperties.Path
                    Properties = $aNewProperties
                }
                if ($Credential) {
                    $hGetADObject["Credential"] = $Credential
                }
                $adoOtherProps = Get-ADObject @hGetADObject -Strict
                foreach ($p in $adoOtherProps.AdditionalProperties.SearchResult.Properties.Keys) {
                    $aProperties = $ado.PSObject.Properties.Name
                    if ($p -notin $aProperties) {
                        $oValue = if ($null -eq $adoOtherProps.AdditionalProperties.SearchResult.Properties[$p]) {
                            $null
                        } else {
                            Convert-ADObjectValue -Property $p -Value $adoOtherProps.AdditionalProperties.SearchResult.Properties[$p]
                        }
                        $ado.$p = $oValue
                    }
                }
            }
        }
        return $aADObject
    }
}

