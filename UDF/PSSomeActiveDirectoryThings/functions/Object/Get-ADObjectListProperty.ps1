function Get-ADObjectListProperty {
    <#
    .SYNOPSIS
        Resolves a DN-list property of an AD object into full AD objects

    .DESCRIPTION
        Reads a multi-valued DN property (e.g., memberOf, member, directReports)
        from an AD object and resolves each DN into a full AD object.

    .PARAMETER ADObject
        The AD object containing the list property.

    .PARAMETER Property
        The property name containing DN values to resolve.

    .PARAMETER ADObjectProperties
        Properties to load for each resolved object.

    .PARAMETER AdditionalProperties
        Extra properties to load for each resolved object.

    .PARAMETER UseGlobalCatalog
        If specified, uses the Global Catalog. Aliases: GC, GlobalCatalog.

    .OUTPUTS
        Custom AD object[]. The resolved AD objects.

    .EXAMPLE
        Get-ADObjectListProperty -ADObject $user -Property "memberof"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADObject,
        [Parameter(Mandatory, Position = 1)]
        [string]$Property,
        [Parameter(Position = 2)]
        [string[]]$ADObjectProperties,
        [Parameter(Position = 3)]
        [string[]]$AdditionalProperties,
        [Alias("GC", "GlobalCatalog")]
        [switch]$UseGlobalCatalog
    )
    Begin {
        if (-not (Test-ContainsArray $ADObject.PSObject.Properties.Name $Property)) {
            Add-ADObjectProperties $ADObject $Property | Out-Null
        }
        $aResult = @()
    }
    Process {
        if ($ADObject.$Property -ne $null) {
            $hGetADDNObjectArgs = @{
                DN = $ADObject.$Property
            }
            if ($ADObjectProperties) {
                $hGetADDNObjectArgs.Properties = $ADObjectProperties
            }
            if ($AdditionalProperties) {
                $hGetADDNObjectArgs.AdditionalProperties = $AdditionalProperties
            }
            $aResult = Get-ADDNObject @hGetADDNObjectArgs -UseGlobalCatalog:$UseGlobalCatalog
        }
    }
    End {
        return $aResult
    }
}
