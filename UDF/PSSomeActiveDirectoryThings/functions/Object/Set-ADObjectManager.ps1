function Set-ADObjectManager {
    <#
    .SYNOPSIS
        Sets or clears the manager of an AD object

    .DESCRIPTION
        Updates the manager attribute of an AD object. Pass $null as Manager
        to clear the current manager.

    .PARAMETER ADObject
        The AD object to modify.

    .PARAMETER Manager
        The AD user object to set as manager, or $null to clear.

    .PARAMETER Credential
        Optional PSCredential for AD authentication.

    .OUTPUTS
        None. The AD object's manager attribute is modified.

    .EXAMPLE
        Set-ADObjectManager -ADObject $user -Manager $managerUser

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADObject,
        [Parameter(Position = 1)]
        [AllowNull()]
        [object]$Manager,
        [pscredential]$Credential
    )
    Begin {
        if ($Manager -and (-not ($Manager.PSTypeNames[0] -eq "ADUser"))) {
            throw "`$Manager is not an ADUser"
        }
        $sManagerDN = if ($Manager) {
            (ConvertFrom-ADSPath -ADObject $Manager).dn
        } else {
            $null
        }
        $hSetADObjectAttr = @{
            manager = $sManagerDN
        }
    }
    Process {
        if ($Credential) {
            Set-ADObjectAttribute -Object $ADObject -Attribute $hSetADObjectAttr -Credential $Credential
        } else {
            Set-ADObjectAttribute -Object $ADObject -Attribute $hSetADObjectAttr
        }
    }
}