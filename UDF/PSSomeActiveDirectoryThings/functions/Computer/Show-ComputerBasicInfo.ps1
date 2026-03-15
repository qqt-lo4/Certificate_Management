function Show-ComputerBasicInfo {
    <#
    .SYNOPSIS
        Displays basic information about an AD computer object

    .DESCRIPTION
        Formats and displays key properties of an AD computer object including
        path, principal name, IP address, description, location, operating system,
        managed by, and creation date. Uses colored output for distinguished names.

    .PARAMETER Computer
        The AD computer object to display.

    .PARAMETER HighlightColor
        The console color used to highlight DN values. Defaults to the current foreground color.

    .OUTPUTS
        None. Outputs formatted information to the console.

    .EXAMPLE
        $computer = Get-ADComputer -Identity "WORKSTATION01" -Properties *
        Show-ComputerBasicInfo -Computer $computer

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory)]
        [object]$Computer,
        [System.ConsoleColor]$HighlightColor = ((Get-Host).ui.rawui.ForegroundColor)
    )
    Begin {
        $aResultProperties = @(@{N="Path"; E={$_.adspath}},
                               @{N="Principal Name"; E={$_."msDS-PrincipalName"}}, 
                               @{N="IP"; E={$_.IP}},
                               @{N="Description"; E={$_.description}}, 
                               @{N="Location"; E={$_.location}}, 
                               @{N="Operating System"; E={$_.operatingSystem}},
                               @{N="Operating System Version"; E={$_.operatingSystemVersion}},
                               @{N="Managed By"; E={$_.managedBy}},
                               @{N="When Created"; E={$_.whencreated}})
        $sDNRegex = "((?<attrib>(E|CN|OU|DC)=)(?<val>[^,:=/]+)(?<comma>,))+((?<attrib>(E|CN|OU|DC)=)(?<val>[^,:=/]+))"
        $sPathRegex = "(?<protocol>[a-zA-Z]+://)?(?<server>[a-zA-Z_.0-6:-]+/)?" + $sDNRegex
        $PropertiesValuesToColor = @(
            @{Property = "Path" ; Pattern = $sPathRegex ; Color = $HighlightColor ; ColorGroups = @("val") ; AllMatches = $true}
            @{Property = "Managed By" ; Pattern = $sPathRegex ; Color = $HighlightColor ; ColorGroups = @("val") ; AllMatches = $true}
        )
    }
    Process {
        Expand-ComputerIPInfo $Computer
        $Computer | Add-ADObjectProperties -Properties $aResultProperties `
                  | Select-Object -Property $aResultProperties `
                  | Format-ListCustom -PropertiesColor Green -PropertiesValuesToColor $PropertiesValuesToColor
    }
}