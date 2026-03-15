function Set-ADObjectExpiration {
    <#
    .SYNOPSIS
        Sets the account expiration date for an AD user or computer

    .DESCRIPTION
        Modifies the accountExpires attribute on an AD user or computer object.
        Can set a specific expiration date or remove expiration entirely.

    .PARAMETER ADObject
        The AD user or computer object to modify.

    .PARAMETER Date
        The expiration date to set.

    .PARAMETER Never
        If specified, removes the account expiration (sets to never expire).

    .PARAMETER Credential
        Optional PSCredential for AD authentication.

    .OUTPUTS
        None. The AD object's accountExpires attribute is modified.

    .EXAMPLE
        Set-ADObjectExpiration -ADObject $user -Date (Get-Date).AddDays(90)

    .EXAMPLE
        Set-ADObjectExpiration -ADObject $user -Never

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    [CmdletBinding(DefaultParameterSetName = "Never")]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADObject,
        [Parameter(Mandatory, Position = 1, ParameterSetName = "Date")]
        [datetime]$Date,
        [Parameter(ParameterSetName = "Never")]
        [switch]$Never,
        [pscredential]$Credential
    )
    if ($ADObject.PSTypeNames[0] -in @("ADUser", "ADComputer")) {
        $dNewValue = if ($PSCmdlet.ParameterSetName -eq "Never") {
            ([int64]::MaxValue).ToString()
        } else {
            $Date.ToFileTimeUtc().ToString()
        }
        if ($Credential) {
            Set-ADObjectAttribute -Object $ADObject -Attribute @{"accountexpires" = $dNewValue} -Credential $Credential
        } else {
            Set-ADObjectAttribute -Object $ADObject -Attribute @{"accountexpires" = $dNewValue}
        }
    } else {
        throw "Object not user or computer"
    }
}