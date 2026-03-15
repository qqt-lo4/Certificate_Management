function Test-ADUserPasswordExpired {
    <#
    .SYNOPSIS
        Tests whether an AD user's password has expired

    .DESCRIPTION
        Checks the msDS-UserPasswordExpiryTimeComputed attribute to determine if the
        user's password has expired. Returns $false if the password is set to never
        expire. Throws an error if the object is not a user.

    .PARAMETER ADUser
        The AD user object to test.

    .OUTPUTS
        [bool]. $true if the password has expired, $false otherwise.

    .EXAMPLE
        Test-ADUserPasswordExpired -ADUser $user

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADUser
    )
    if ($ADUser.PSTypeNames[0] -in @("ADUser")) {
        if (-not (Test-ContainsArray $ADUser.PSObject.Properties.Name "msDS-UserPasswordExpiryTimeComputed")) {
            Add-ADObjectProperties -ADObject $ADUser -Properties "msDS-UserPasswordExpiryTimeComputed" | Out-Null
        }
        $oValue = ($ADUser."msDS-UserPasswordExpiryTimeComputed")
        $bPasswordExpired = if ($oValue.ToString() -eq "Never") { $false } else { ($ADUser."msDS-UserPasswordExpiryTimeComputed").GetDate() -lt (Get-Date) }
        return $bPasswordExpired
    } else {
        throw "Object not user or computer"
    }
}
