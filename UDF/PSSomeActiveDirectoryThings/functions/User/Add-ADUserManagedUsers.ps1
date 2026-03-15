function Add-ADUserManagedUsers {
    <#
    .SYNOPSIS
        Sets a user as the manager of one or more AD users

    .DESCRIPTION
        Assigns the specified AD user as the manager for each user in the ManagedUsers
        list by calling Set-ADObjectManager. Throws an error if any object is not a user.

    .PARAMETER ADUser
        The AD user object to set as manager.

    .PARAMETER ManagedUsers
        One or more AD user objects that will have their manager set.

    .PARAMETER Credential
        Optional credentials for the directory operation.

    .OUTPUTS
        None.

    .EXAMPLE
        Add-ADUserManagedUsers -ADUser $manager -ManagedUsers $user1, $user2

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADUser,
        [Parameter(Mandatory, Position = 1)]
        [object[]]$ManagedUsers,
        [pscredential]$Credential
    )
    Begin {
        if ($ADUser.PSTypeNames[0] -ne "ADuser") {
            throw "`$ADuser is not a user"
        }
        $hAddManager = @{
            Manager = $ADUser
        }
        if ($Credential) {
            $hAddManager.Credential = $Credential
        }    
    }
    Process {
        foreach ($oUser in $ManagedUsers) {
            if ($oUser.PSTypeNames[0] -eq "ADuser") {
                Set-ADObjectManager -ADObject $oUser @hAddManager
            } else {
                throw "$($oUser.name) is not a user"
            }
        }
    }
}
