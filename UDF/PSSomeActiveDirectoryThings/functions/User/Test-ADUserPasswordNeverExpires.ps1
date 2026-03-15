function Test-ADUserPasswordNeverExpires {
    <#
    .SYNOPSIS
        Tests whether an AD user's password is set to never expire

    .DESCRIPTION
        Checks the ADS_UF_DONT_EXPIRE_PASSWD flag in the user's UserAccountControl
        attribute. Throws an error if the object is not a user.

    .PARAMETER ADUser
        The AD user object to test.

    .OUTPUTS
        [bool]. $true if the password never expires, $false otherwise.

    .EXAMPLE
        Test-ADUserPasswordNeverExpires -ADUser $user

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADUser
    )
    if ($ADUser.PSTypeNames[0] -in @("ADUser")) {
        if (-not (Test-ContainsArray $ADUser.PSObject.Properties.Name "useraccountcontrol")) {
            Add-ADObjectProperties -ADObject $ADUser -Properties "useraccountcontrol" | Out-Null
        }
        return (Convert-ADUACBit $ADUser."useraccountcontrol" ([ADS_USER_FLAG_ENUM]::ADS_UF_DONT_EXPIRE_PASSWD))
    } else {
        throw "Object not user"
    }
}
