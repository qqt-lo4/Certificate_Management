function Reset-ADUserPassword {
    <#
    .SYNOPSIS
        Resets an AD user's password and unlocks the account

    .DESCRIPTION
        Sets a new password for the specified AD user, clears the lockout time to
        unlock the account, and optionally forces the user to change their password
        at next logon.

    .PARAMETER User
        The AD user object whose password will be reset.

    .PARAMETER Credential
        Optional credentials for connecting to the directory entry.

    .PARAMETER Password
        The new password as a SecureString.

    .PARAMETER MustChangePassword
        If specified, forces the user to change their password at next logon.

    .OUTPUTS
        None.

    .EXAMPLE
        Reset-ADUserPassword -User $adUser -Password $securePassword -MustChangePassword

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [Object]$User,
        [pscredential]$Credential,
        [securestring]$Password,
        [switch]$MustChangePassword
    )
    $sPath = if ($User.adspath) {
        $User.adspath
    } else {
        $User.Path
    }
    $deUser = Get-DirectoryEntry -Path $sPath -Credential $Credential
    $UnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
    $deUser.Properties["LockOutTime"].Value = 0
    if ($MustChangePassword) {
        $deUser.Properties["pwdlastset"].Value = 0
    }
    $deUser.Invoke("SetPassword", @($UnsecurePassword))
    $deUser.CommitChanges()
    $deUser.Close()
}
