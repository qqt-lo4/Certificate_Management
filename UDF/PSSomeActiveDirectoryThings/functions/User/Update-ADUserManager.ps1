function Update-ADUserManager {
    <#
    .SYNOPSIS
        Updates the manager for one or more AD users

    .DESCRIPTION
        Sets the specified manager for each AD user in the list. Both the manager
        and the users must be ADuser objects. Throws an error otherwise.

    .PARAMETER ADUsers
        One or more AD user objects to update.

    .PARAMETER Manager
        The AD user object to set as manager for all specified users.

    .OUTPUTS
        None.

    .EXAMPLE
        Update-ADUserManager -ADUsers $user1, $user2 -Manager $newManager

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object[]]$ADUsers,
        [Parameter(Mandatory, Position = 1)]
        [object]$Manager
    )
    Begin {
        if (-not ($Manager.PSTypeNames[0] -eq "ADuser")) {
            throw "`$Manager is not an ADuser"
        }    
    }
    Process {
        foreach ($oUser in $ADUsers) {
            if ($oUser.PSTypeNames[0] -eq "ADuser") {
                Set-ADObjectManager -ADObject $oUser -Manager $Manager
            } else {
                throw "`$oUser is not an ADuser"
            }
        }
    }
}