function Show-GroupBasicInfo {
    <#
    .SYNOPSIS
        Displays basic information about an AD group object

    .DESCRIPTION
        Formats and displays key properties of an AD group: path, principal name,
        description, email, managed by, and creation date with colored DN highlighting.

    .PARAMETER Group
        The AD group object to display.

    .PARAMETER HighlightColor
        Console color for DN value highlighting. Defaults to the current foreground color.

    .OUTPUTS
        None. Outputs formatted information to the console.

    .EXAMPLE
        Show-GroupBasicInfo -Group $group

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory)]
        [object]$Group,
        [System.ConsoleColor]$HighlightColor = ((Get-Host).ui.rawui.ForegroundColor)
    )
    Begin {
        $aResultProperties = @(@{N="Path"; E={$_.adspath}},
                               @{N="Principal Name"; E={$_."msDS-PrincipalName"}}, 
                               @{N="Description"; E={$_.description}}, 
                               @{N="Email address"; E={$_.mail}},
                               @{N="Managed By"; E={$_.manager}}, 
                               @{N="When Created"; E={$_.whencreated}})
        $sDNRegex = "((?<attrib>(E|CN|OU|DC)=)(?<val>[^,:=/]+)(?<comma>,))+((?<attrib>(E|CN|OU|DC)=)(?<val>[^,:=/]+))"
        $sPathRegex = "(?<protocol>[a-zA-Z]+://)?(?<server>[a-zA-Z_.0-6:-]+/)?" + $sDNRegex
        $PropertiesValuesToColor = @(
            @{Property = "Path" ; Pattern = $sPathRegex ; Color = $HighlightColor ; ColorGroups = @("val") ; AllMatches = $true}
            @{Property = "Managed By" ; Pattern = $sPathRegex ; Color = $HighlightColor ; ColorGroups = @("val") ; AllMatches = $true}
        )
    }
    Process {
        $oResult = $Group | Add-ADObjectProperties -Properties $aResultProperties
        $oResult | Select-Object -Property $aResultProperties `
                 | Format-ListCustom -PropertiesColor Green -PropertiesValuesToColor $PropertiesValuesToColor
    }
}
