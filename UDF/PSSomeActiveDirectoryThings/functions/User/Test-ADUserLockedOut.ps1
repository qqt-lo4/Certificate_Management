function Test-ADUserLockedOut {
    <#
    .SYNOPSIS
        Tests whether an AD user account is locked out

    .DESCRIPTION
        Checks the ADS_UF_LOCKOUT flag in the computed UserAccountControl attribute
        (msDS-User-Account-Control-Computed). Throws an error if the object is not a user.

    .PARAMETER ADUser
        The AD user object to test.

    .OUTPUTS
        [bool]. $true if the account is locked out, $false otherwise.

    .EXAMPLE
        Test-ADUserLockedOut -ADUser $user

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADUser
    )
    if ($ADUser.PSTypeNames[0] -in @("ADUser")) {
        if (-not (Test-ContainsArray $ADUser.PSObject.Properties.Name "msDS-User-Account-Control-Computed")) {
            Add-ADObjectProperties -ADObject $ADUser -Properties "msDS-User-Account-Control-Computed" | Out-Null
        }
        return (Convert-ADUACBit $ADUser."msDS-User-Account-Control-Computed" ([ADS_USER_FLAG_ENUM]::ADS_UF_LOCKOUT))
    } else {
        throw "Object not user"
    }
}