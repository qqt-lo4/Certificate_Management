function Test-ADObjectEnabled {
    <#
    .SYNOPSIS
        Tests if an AD account is enabled

    .DESCRIPTION
        Returns $true if the AD account is not disabled (inverse of Test-ADObjectDisabled).

    .PARAMETER ADObject
        The AD user or computer object to test.

    .OUTPUTS
        System.Boolean. $true if the account is enabled.

    .EXAMPLE
        Test-ADObjectEnabled -ADObject $user

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADObject
    )
    return -not (Test-ADObjectDisabled $ADObject)
}