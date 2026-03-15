function Show-UserLogonInfo {
    <#
    .SYNOPSIS
        Displays formatted logon information for an AD user

    .DESCRIPTION
        Formats and displays logon-related properties of an AD user object with colored
        output. Shows account status, password state, lockout info, and reasons the user
        cannot log on. Highlights problematic values (disabled, expired, locked) in red.

    .PARAMETER User
        The AD user object to display logon information for.

    .PARAMETER HighlightColor
        Console color for DN value highlighting. Defaults to the current foreground color.

    .OUTPUTS
        None. Outputs formatted information to the console.

    .EXAMPLE
        Show-UserLogonInfo -User $adUser

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory)]
        [object]$User,
        [System.ConsoleColor]$HighlightColor = ((Get-Host).ui.rawui.ForegroundColor)
    )
    Begin {
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
        $aUserLogonProperties = @("msDS-PrincipalName", "name", "samaccountname", "pwdlastset", "msDS-UserPasswordExpiryTimeComputed", "useraccountcontrol", "msDS-User-Account-Control-Computed", "accountexpires", "badpasswordtime", "badpwdcount", "lockouttime", "lastlogon")
    }
    Process {
        if (-not (Test-ContainsArray $User.PSObject.Properties.Name $aUserLogonProperties)) {
            Expand-UserLogonInfo $User
        }
        $UserLogonInfo = $User | Select-Object @{N="Path"; E={$_.adspath}},
                                                @{N="SamAccountName"; E={$_.samaccountname}},
                                                @{N="Account Disabled"; E={$_."AccountDisabled"}},
                                                @{N="Account Expires"; E={$_.accountexpires}}, 
                                                @{N="Account Expired"; E={$_."AccountExpired"}}, 
                                                @{N="Password Never Expires"; E={$_.PasswordNeverExpires}}, 
                                                @{N="Password Cannot Change"; E={$_.PasswordCannotChange}},
                                                @{N="Password Must Change"; E={$_.PasswordMustChange}},
                                                @{N="Password Last Set"; E={$_.pwdlastset}}, 
                                                @{N="User Password Expiry Time Computed"; E={$_."msDS-UserPasswordExpiryTimeComputed"}}, 
                                                @{N="Password Expired"; E={$_.PasswordExpired}}, 
                                                @{N="Last Bad Password Time"; E={$_.badpasswordtime}},
                                                @{N="Bad Password Count"; E={$_.badPwdCount}},
                                                @{N="Locked Out"; E={$_.LockedOut}},
                                                @{N="Last Log On"; E={$_.LastLogOn}},
                                                "Can't Log Reasons"
        
        $sDNRegex = "((?<attrib>(E|CN|OU|DC)=)(?<val>[^,:=/]+)(?<comma>,))+((?<attrib>(E|CN|OU|DC)=)(?<val>[^,:=/]+))"
        $sPathRegex = "(?<protocol>[a-zA-Z]+://)?(?<server>[a-zA-Z_.0-6:-]+/)?" + $sDNRegex

        $UserLogonInfo | Format-ListCustom -PropertiesColor Green -PropertyAlign Left -PropertiesValuesToColor @(
            @{Property = "Path" ; Pattern = $sPathRegex ; Color = $HighlightColor ; ColorGroups = @("val") ; AllMatches = $true}
            @{Property = "Account Disabled" ; Pattern = "[Tt]rue" ; Color = "Red" }
            @{Property = "Account Expired" ; Pattern = "[Tt]rue" ; Color = "Red" }
            @{Property = "Password Must Change" ; Pattern = "[Tt]rue" ; Color = "Red" }
            @{Property = "Password Expired" ; Pattern = "[Tt]rue" ; Color = "Red" }
            @{Property = "Locked Out" ; Pattern = "[Tt]rue" ; Color = "Red" }
            @{Property = "Can't Log Reasons" ; Color = "Red" }
        )
    }
}
