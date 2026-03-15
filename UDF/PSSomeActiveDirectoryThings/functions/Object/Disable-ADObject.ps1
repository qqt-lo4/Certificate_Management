function Disable-ADObject {
    <#
    .SYNOPSIS
        Disables an AD user or computer account

    .DESCRIPTION
        Sets the ADS_UF_ACCOUNTDISABLE flag in the UserAccountControl attribute
        to disable the account.

    .PARAMETER ADObject
        The AD object to disable.

    .PARAMETER Credential
        Optional PSCredential for AD authentication.

    .OUTPUTS
        None. The AD account is disabled.

    .EXAMPLE
        Disable-ADObject -ADObject $user

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADObject,
        [pscredential]$Credential
    )
    Set-ADObjectUserAccountControlValue @PSBoundParameters -Set -Attribute ([ADS_USER_FLAG_ENUM]::ADS_UF_ACCOUNTDISABLE)
}
