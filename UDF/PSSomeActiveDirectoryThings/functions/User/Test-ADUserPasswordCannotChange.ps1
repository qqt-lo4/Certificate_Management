function Test-ADUserPasswordCannotChange {
    <#
    .SYNOPSIS
        Tests whether an AD user is prevented from changing their password

    .DESCRIPTION
        Converts the AD user to a UserPrincipal object and checks the
        UserCannotChangePassword property. Throws an error if the object is not a user.

    .PARAMETER ADUser
        The AD user object to test.

    .OUTPUTS
        [bool]. $true if the user cannot change their password, $false otherwise.

    .EXAMPLE
        Test-ADUserPasswordCannotChange -ADUser $user

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADUser
    )
    if ($ADUser.PSTypeNames[0] -in @("ADUser")) {
        $oUserPrincipal = Convert-ADUserToUserPrincipal -ADObject $ADUser
        return $oUserPrincipal.UserCannotChangePassword
    } else {
        throw "Object not user or computer"
    }
}
