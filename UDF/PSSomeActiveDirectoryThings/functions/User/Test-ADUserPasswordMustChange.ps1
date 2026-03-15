function Test-ADUserPasswordMustChange {
    <#
    .SYNOPSIS
        Tests whether an AD user must change their password at next logon

    .DESCRIPTION
        Checks if the pwdLastSet attribute is null or 0, which indicates the user
        must change their password at next logon. Throws an error if the object is not a user.

    .PARAMETER ADUser
        The AD user object to test.

    .OUTPUTS
        [bool]. $true if the user must change their password, $false otherwise.

    .EXAMPLE
        Test-ADUserPasswordMustChange -ADUser $user

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADUser
    )
    if ($ADUser.PSTypeNames[0] -in @("ADUser")) {
        if (-not (Test-ContainsArray $ADUser.PSObject.Properties.Name "pwdlastset")) {
            Add-ADObjectProperties -ADObject $ADUser -Properties "pwdlastset" | Out-Null
        }
        return ($null -eq $ADUser."pwdlastset") -or ($ADUser."pwdlastset" -eq 0)
    } else {
        throw "Object not user"
    }
}
