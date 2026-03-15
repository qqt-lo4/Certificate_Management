function Set-ADObjectUserAccountControlValue {
    <#
    .SYNOPSIS
        Sets or unsets a UserAccountControl flag on an AD object

    .DESCRIPTION
        Modifies individual bits of the UserAccountControl attribute using
        bitwise OR (set) or XOR (unset) operations on AD user or computer objects.

    .PARAMETER ADObject
        The AD user or computer object to modify.

    .PARAMETER Attribute
        The ADS_USER_FLAG_ENUM value to set or unset.

    .PARAMETER Set
        If specified, sets (enables) the flag.

    .PARAMETER Unset
        If specified, unsets (disables) the flag.

    .PARAMETER Credential
        Optional PSCredential for AD authentication.

    .OUTPUTS
        None. The UserAccountControl attribute is modified.

    .EXAMPLE
        Set-ADObjectUserAccountControlValue -ADObject $user -Attribute DONT_EXPIRE_PASSWD -Set

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    [CmdletBinding(DefaultParameterSetName = "Set")]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADObject,
        [Parameter(Mandatory, Position = 1)]
        [ADS_USER_FLAG_ENUM]$Attribute,
        [Parameter(ParameterSetName = "Set")]
        [switch]$Set,
        [Parameter(ParameterSetName = "Unset")]
        [switch]$Unset,
        [pscredential]$Credential
    )
    if ($ADObject.PSTypeNames[0] -in @("ADUser", "ADComputer")) {
        if (-not (Test-ContainsArray $ADObject.PSObject.Properties.Name "useraccountcontrol")) {
            Add-ADObjectProperties -ADObject $ADObject -Properties "useraccountcontrol" | Out-Null
        }
        $oUAC = $ADObject.useraccountcontrol
        $iNewVal = if ($PSCmdlet.ParameterSetName -eq "Set") {
            $oUAC -bor $Attribute.value__
        } else {
            $oUAC -bxor $Attribute.value__
        }
        Write-Verbose "`$iNewVal = $iNewVal"
        if ($Credential) {
            Set-ADObjectAttribute -Object $ADObject -Attribute @{"useraccountcontrol" = $iNewVal} -Credential $Credential
        } else {
            Set-ADObjectAttribute -Object $ADObject -Attribute @{"useraccountcontrol" = $iNewVal}
        }
    } else {
        throw "Incompatible `$ADObject type"
    }
}