function Test-ADObjectExpired {
    <#
    .SYNOPSIS
        Tests if an AD account has expired

    .DESCRIPTION
        Checks the accountExpires attribute to determine if the account
        expiration date has passed.

    .PARAMETER ADObject
        The AD user or computer object to test.

    .OUTPUTS
        System.Boolean. $true if the account has expired.

    .EXAMPLE
        Test-ADObjectExpired -ADObject $user

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADObject
    )
    if ($ADObject.PSTypeNames[0] -in @("ADUser", "ADComputer")) {
        if (-not (Test-ContainsArray $ADObject.PSObject.Properties.Name "accountexpires")) {
            Add-ADObjectProperties -ADObject $ADObject -Properties "accountexpires" | Out-Null
        }
        $oValue = $ADObject.accountexpires
        if ($null -eq $oValue) {
            return $false
        } else {
            return ($oValue.ToString() -ne "Never") -and ($oValue.GetDate() -lt (Get-Date))
        }
    } else {
        throw "Object not user or computer"
    }
}