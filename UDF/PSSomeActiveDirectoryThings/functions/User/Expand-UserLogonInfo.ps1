function Expand-UserLogonInfo {
    <#
    .SYNOPSIS
        Expands an AD user object with computed logon properties

    .DESCRIPTION
        Adds computed logon-related properties to an AD user object by reading
        UserAccountControl flags. Adds: PasswordNeverExpires, AccountDisabled,
        PasswordCannotChange, PasswordExpired, LockedOut, PasswordMustChange,
        AccountExpired, and a summary of reasons the user cannot log on.

    .PARAMETER User
        The AD user object to expand with logon properties.

    .OUTPUTS
        [object]. The user object with added logon properties (modified in place).

    .EXAMPLE
        Expand-UserLogonInfo -User $adUser

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$User
    )

    Begin {
        function Add-UserLogonProperty {
            Param(
                [Parameter(Mandatory, Position = 0)]
                [object]$User, 
                [Parameter(Mandatory, Position = 1)]
                [string]$PropertyName,
                [Parameter(Mandatory, Position = 2)]
                [object]$UACPropertyValue,
                [Parameter(Mandatory, Position = 3)]
                [ADS_USER_FLAG_ENUM]$UACBit
            )
            if ($PropertyName -notin $User.PSObject.Properties.Name) {
                $User | Add-Member -NotePropertyname $PropertyName -NotePropertyValue (Convert-ADUACBit $UACPropertyValue $UACBit)
            }
        }

        function Add-UserLogonProperties {
            Param(
                [Parameter(Mandatory, Position = 0)]
                [object]$User, 
                [Parameter(Mandatory, Position = 1)]
                [AllowNull()]
                [object]$UAC,
                [Parameter(Mandatory, Position = 2)]
                [AllowNull()]
                [object]$ComputedUAC,
                [Parameter(Mandatory, Position = 3)]
                [AllowNull()]
                [object]$PwdLastSet,
                [Parameter(Mandatory, Position = 4)]
                [AllowNull()]
                [object]$AccountExpires
            )
            $oPropUAC = $UAC
            Add-UserLogonProperty $User "PasswordNeverExpires" $oPropUAC ([ADS_USER_FLAG_ENUM]::ADS_UF_DONT_EXPIRE_PASSWD)
            Add-UserLogonProperty $User "AccountDisabled" $oPropUAC ([ADS_USER_FLAG_ENUM]::ADS_UF_ACCOUNTDISABLE)
            Add-UserLogonProperty $User "PasswordCannotChange" $oPropUAC ([ADS_USER_FLAG_ENUM]::ADS_UF_PASSWD_CANT_CHANGE)
            $oPropUAC = $ComputedUAC
            Add-UserLogonProperty $User "PasswordExpired" $oPropUAC ([ADS_USER_FLAG_ENUM]::ADS_UF_PASSWORD_EXPIRED)
            Add-UserLogonProperty $User "LockedOut" $oPropUAC ([ADS_USER_FLAG_ENUM]::ADS_UF_LOCKOUT)
            if ("PasswordMustChange" -notin $User.PSObject.Properties.Name) {
                $User | Add-Member -NotePropertyname "PasswordMustChange" -NotePropertyValue (($PwdlastSet -eq $null) -or ($PwdlastSet -eq 0))
            }
            if ("AccountExpired" -notin $User.PSObject.Properties.Name) {
                if ($null -eq $AccountExpires) {
                    $User | Add-Member -NotePropertyname "AccountExpired" -NotePropertyValue $false
                } else {
                    $User | Add-Member -NotePropertyname "AccountExpired" -NotePropertyValue (($AccountExpires.ToString() -ne "Never") -and ($AccountExpires.GetDate() -lt (Get-Date)))
                }
            }
            if ("Can't Log Reasons" -notin $User.PSObject.Properties.Name) { 
                $aCantLogReasons = @()
                if ($User.AccountDisabled) { $aCantLogReasons += "Account Disabled" }
                if ($User.AccountExpired) { $aCantLogReasons += "Account Expired" }
                if ($User.PasswordExpired) { $aCantLogReasons += "Password Expired" }
                if ($User.LockedOut) { $aCantLogReasons += "User locked out" }
                if ($User.PasswordMustChange) { $aCantLogReasons += "User must change password" }
                $User | Add-Member -NotePropertyname "Can't Log Reasons" -NotePropertyValue ($aCantLogReasons -join ", ")    
            }
        }

        function Test-ContainsArray {
            Param(
                [Parameter(Mandatory, Position = 0)]
                [object[]]$ReferenceArray,
                [Parameter(Mandatory, Position = 1)]
                [object[]]$ArrayContained
            )
            $oCompareResults = Compare-Object -ReferenceObject $ReferenceArray -DifferenceObject $ArrayContained -IncludeEqual -ExcludeDifferent
            return ($oCompareResults.Count -eq $ArrayContained.Count)
        }

        $aAdditionalProperties = @("msDS-PrincipalName", "name", "samaccountname", "pwdlastset", "msDS-UserPasswordExpiryTimeComputed", "useraccountcontrol", "msDS-User-Account-Control-Computed", "accountexpires", "badpasswordtime", "badpwdcount", "lockouttime", "lastlogon")
    }

    Process {
        if ($User.PSTypeNames[0] -in @("ADUser", "ADComputer")) {
            if (-not (Test-ContainsArray $User.PSObject.Properties.Name $aAdditionalProperties)) {
                Add-ADObjectProperties -ADObject $User -Properties $aAdditionalProperties | Out-Null
            }
            Add-UserLogonProperties $User $User.useraccountcontrol $User."msDS-User-Account-Control-Computed" $User.pwdlastset $User.accountexpires    
        } else {
            return $User
        }
    }
}
