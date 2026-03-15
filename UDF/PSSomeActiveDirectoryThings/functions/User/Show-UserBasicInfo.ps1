function Show-UserBasicInfo {
    <#
    .SYNOPSIS
        Displays basic information for an AD user with colored output

    .DESCRIPTION
        Formats and displays key user properties (name, title, department, contact info,
        manager, etc.) with colored DN highlighting. Also shows logon issues if any
        are detected.

    .PARAMETER User
        The AD user object to display basic information for.

    .PARAMETER HighlightColor
        Console color for DN value highlighting. Defaults to the current foreground color.

    .OUTPUTS
        None. Outputs formatted information to the console.

    .EXAMPLE
        Show-UserBasicInfo -User $adUser

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
        $aResultProperties = @(@{N="Path"; E={$_.adspath}},
                               @{N="Principal Name"; E={$_."msDS-PrincipalName"}}, 
                               @{N="First Name"; E={$_.givenname}},
                               @{N="Last Name"; E={$_.sn}},
                               @{N="Display Name"; E={$_.displayname}}, 
                               @{N="Description"; E={$_.description}}, 
                               @{N="Title"; E={$_.title}}, 
                               @{N="Department"; E={$_.department}}, 
                               @{N="Company"; E={$_.company}}, 
                               @{N="Office"; E={$_.physicalDeliveryOfficeName}}, 
                               @{N="Phone"; E={$_.telephoneNumber + " " + $_.otherTelephone}}, 
                               @{N="Email address"; E={$_.mail}},
                               @{N="Managed By"; E={$_.manager}}, 
                               @{N="When Created"; E={$_.whencreated}})
        $sDNRegex = "((?<attrib>(E|CN|OU|DC)=)(?<val>[^,:=/]+)(?<comma>,))+((?<attrib>(E|CN|OU|DC)=)(?<val>[^,:=/]+))"
        $sPathRegex = "(?<protocol>[a-zA-Z]+://)?(?<server>[a-zA-Z_.0-6:-]+/)?" + $sDNRegex
        $PropertiesValuesToColor = @(
            @{Property = "Path" ; Pattern = $sPathRegex ; Color = $HighlightColor ; ColorGroups = @("val") ; AllMatches = $true}
            @{Property = "Managed By" ; Pattern = $sPathRegex ; Color = $HighlightColor ; ColorGroups = @("val") ; AllMatches = $true}
            @{Property = "Can't Log Reasons" ; Color = "Red"}
        )
    }
    Process {
        Expand-UserLogonInfo $User
        $oResult = $User | Add-ADObjectProperties -Properties $aResultProperties
        if (($null -ne $User."Can't Log Reasons") -and ($User."Can't Log Reasons" -ne "")) {
            $aResultProperties += "Can't Log Reasons"
        }
        $oResult | Select-Object -Property $aResultProperties `
                 | Format-ListCustom -PropertiesColor Green -PropertiesValuesToColor $PropertiesValuesToColor
    }
}