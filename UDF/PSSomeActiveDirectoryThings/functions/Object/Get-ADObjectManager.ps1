function Get-ADObjectManager {
    <#
    .SYNOPSIS
        Retrieves the manager of an AD object

    .DESCRIPTION
        Reads the manager attribute of an AD object and returns the manager
        as a full AD object. Returns $null if no manager is set.

    .PARAMETER ADObject
        The AD object to get the manager for.

    .OUTPUTS
        Custom AD object representing the manager, or $null.

    .EXAMPLE
        Get-ADObjectManager -ADObject $user

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADObject
    )
    Begin {
        $aNewProperties = @("objectclass", "manager")    
    }
    Process {
        $ADObject | Add-ADObjectProperties -Properties $aNewProperties | Out-Null
        if ($ADObject.manager) {
            return Get-ADObject -Identity $ADObject.manager
        } else {
            return $null
        }
    }
}
