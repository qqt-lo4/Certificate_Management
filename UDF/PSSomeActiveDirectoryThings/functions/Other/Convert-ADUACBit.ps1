function Convert-ADUACBit {
    <#
    .SYNOPSIS
        Tests whether a specific UserAccountControl flag is set

    .DESCRIPTION
        Performs a bitwise AND operation on the UserAccountControl value to determine
        if a specific ADS_USER_FLAG_ENUM flag is set. Returns $true if the flag is
        present, $false otherwise.

    .PARAMETER InputData
        The UserAccountControl integer value to test.

    .PARAMETER UACProperty
        The ADS_USER_FLAG_ENUM flag to check for.

    .OUTPUTS
        [bool]. $true if the specified flag is set, $false otherwise.

    .EXAMPLE
        Convert-ADUACBit -InputData $user.userAccountControl -UACProperty ADS_UF_ACCOUNTDISABLE

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$InputData,
        [Parameter(Mandatory, Position = 1)]
        [ADS_USER_FLAG_ENUM]$UACProperty
    )
    return (($InputData -band $UACProperty.value__) -eq $UACProperty.value__)
}
