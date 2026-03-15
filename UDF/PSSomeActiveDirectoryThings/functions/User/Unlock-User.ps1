function Unlock-User {
    <#
    .SYNOPSIS
        Unlocks one or more locked AD user accounts

    .DESCRIPTION
        Checks if each user is locked out and resets the lockoutTime attribute to 0
        to unlock the account. Supports pipeline input. Skips users that are not
        locked out.

    .PARAMETER User
        One or more AD user objects to unlock. Accepts pipeline input.

    .PARAMETER Credential
        Optional credentials for connecting to the directory entry.

    .OUTPUTS
        None.

    .EXAMPLE
        Unlock-User -User $lockedUser

    .EXAMPLE
        $lockedUsers | Unlock-User

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object[]]$User,
        [pscredential]$Credential
    )
    Begin {
        $aUsers = @()
    }
    Process {
        $aUsers += $User
    }
    End {
        foreach ($u in $aUsers) {
            if (Test-ADUserLockedOut -ADUser $u) {
                try {
                    $oUserDE = Get-DirectoryEntry -Path $u.adspath -Credential $Credential
                    $oUserDE.Properties["lockoutTime"].Value = 0
                    $oUserDE.CommitChanges()
                    Write-Verbose "User $($u.samaccountname) is now unlocked"    
                } catch {
                    throw "Failed to unlock $($u.samaccountname)"
                }
            } else {
                Write-Verbose "User $($u.samaccountname) is not locked out"
            }
        }
    }
}