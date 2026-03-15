function Test-ADObjectDisabled {
    <#
    .SYNOPSIS
        Tests if an AD account is disabled

    .DESCRIPTION
        Checks the ADS_UF_ACCOUNTDISABLE bit in the UserAccountControl attribute
        to determine if the account is disabled.

    .PARAMETER ADObject
        The AD user or computer object to test.

    .OUTPUTS
        System.Boolean. $true if the account is disabled.

    .EXAMPLE
        Test-ADObjectDisabled -ADObject $user

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADObject
    )
    if ($ADObject.PSTypeNames[0] -in @("ADUser", "ADComputer")) {
        if (-not (Test-ContainsArray $ADObject.PSObject.Properties.Name "useraccountcontrol")) {
            Add-ADObjectProperties -ADObject $ADObject -Properties "useraccountcontrol" | Out-Null
        }
        $bAccountDisabled = (Convert-ADUACBit $ADObject."useraccountcontrol" ([ADS_USER_FLAG_ENUM]::ADS_UF_ACCOUNTDISABLE))
        return $bAccountDisabled
    } else {
        throw "Object not user or computer"
    }
}