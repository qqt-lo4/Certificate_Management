function Enable-ADObject {
    <#
    .SYNOPSIS
        Enables an AD user or computer account

    .DESCRIPTION
        Clears the ADS_UF_ACCOUNTDISABLE flag in the UserAccountControl attribute
        to enable the account.

    .PARAMETER ADObject
        The AD object to enable.

    .PARAMETER Credential
        Optional PSCredential for AD authentication.

    .OUTPUTS
        None. The AD account is enabled.

    .EXAMPLE
        Enable-ADObject -ADObject $user

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADObject,
        [pscredential]$Credential
    )
    Set-ADObjectUserAccountControlValue @PSBoundParameters -Unset -Attribute ([ADS_USER_FLAG_ENUM]::ADS_UF_ACCOUNTDISABLE)
}
