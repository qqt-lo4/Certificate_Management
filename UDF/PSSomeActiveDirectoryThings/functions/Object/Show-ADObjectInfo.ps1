function Show-ADObjectInfo {
    <#
    .SYNOPSIS
        Displays specified properties of an AD object

    .DESCRIPTION
        Loads and displays the requested properties of an AD object in a
        formatted list. Supports both string property names and calculated
        property hashtables.

    .PARAMETER ADObject
        The AD object to display information for.

    .PARAMETER Property
        The properties to display (string names or calculated property hashtables).

    .OUTPUTS
        None. Outputs formatted information to the console.

    .EXAMPLE
        Show-ADObjectInfo -ADObject $user -Property "name","mail","department"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADObject,
        [Parameter(Mandatory, Position = 1)]
        [object[]]$Property
    )
    Begin {
        $aProperties = @()
        foreach ($p in $Property) {
            if ($p -is [string]) {
                $aProperties += $p
            } elseif ($p -is [hashtable]) { # -or ($p -is [ordered])) {
                $sbExpression = if ($p["e"]) { $p["e"] } elseif ($p["E"]) { $p["E"]} else { $p["expression"] }
                $sProperty = ($sbExpression.ToString().Trim() | Select-String -Pattern "^\`$_`.`"?(?<property>[^.`"]+)").Matches.Groups | Where-Object { $_.Name -eq "property" }
                $aProperties += $sProperty.Value
            }
        }
        if (-not (Test-ContainsArray $ADObject.PSObject.Properties.Name $aProperties)) {
            Add-ADObjectProperties $ADObject $aProperties | Out-Null
        }
    }
    Process {
        $ADObject | Select-Object -Property $Property | Format-List | Out-Host
    }
}