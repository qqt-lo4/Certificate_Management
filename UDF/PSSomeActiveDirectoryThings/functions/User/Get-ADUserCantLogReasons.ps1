function Get-ADUserCantLogReasons {
    <#
    .SYNOPSIS
        Returns the reasons an AD user cannot log on

    .DESCRIPTION
        Checks multiple conditions (account disabled, account expired, password expired,
        locked out, must change password) and returns a list of reasons preventing
        the user from logging on.

    .PARAMETER ADUser
        The AD user object to check.

    .OUTPUTS
        [string[]]. An array of reason strings, or an empty array if the user can log on.

    .EXAMPLE
        Get-ADUserCantLogReasons -ADUser $user
        # Returns @("Account Disabled", "Password Expired")

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$ADUser
    )
    $aCantLogReasons = @()
    if (Test-ADObjectDisabled $ADUser) { $aCantLogReasons += "Account Disabled" }
    if (Test-ADObjectExpired $ADUser) { $aCantLogReasons += "Account Expired" }
    if (Test-ADUserPasswordExpired $ADUser) { $aCantLogReasons += "Password Expired" }
    if (Test-ADUserLockedOut $ADUser) { $aCantLogReasons += "User locked out" }
    if (Test-ADUserPasswordMustChange $ADUser) { $aCantLogReasons += "User must change password" }
    return $aCantLogReasons
}