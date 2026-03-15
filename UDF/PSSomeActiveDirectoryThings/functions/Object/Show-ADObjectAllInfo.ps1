function Show-ADObjectAllInfo {
    <#
    .SYNOPSIS
        Displays all properties of an AD object with colored DN highlighting

    .DESCRIPTION
        Formats and displays all properties of an AD object using colored output
        for distinguished name values (adspath, memberof, manager, directreports, etc.).
        Optionally sorts the memberOf list.

    .PARAMETER ADObject
        The AD object to display all information for.

    .PARAMETER SortMemberOf
        If specified, sorts the memberOf list alphabetically.

    .PARAMETER HighlightColor
        Console color for DN value highlighting. Defaults to the current foreground color.

    .OUTPUTS
        None. Outputs formatted information to the console.

    .EXAMPLE
        Show-ADObjectAllInfo -ADObject $user -SortMemberOf

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory)]
        [object]$ADObject,
        [switch]$SortMemberOf,
        [System.ConsoleColor]$HighlightColor = ((Get-Host).ui.rawui.ForegroundColor)
    )
    Begin {
        
    }
    Process {
        #$ADObject | Select-Object -Property * | Format-List | Out-Host
        $sDNRegex = "((?<attrib>(E|CN|OU|DC)=)(?<val>[^,:=/]+)(?<comma>,))+((?<attrib>(CN|OU|DC)=)(?<val>[^,:=/]+))"
        $sPathRegex = "(?<protocol>[a-zA-Z]+://)?(?<server>[a-zA-Z_.0-6:-]+/)?" + $sDNRegex
        if ($SortMemberOf -and $ADObject.memberof) {
            $ADObject.memberof = $ADObject.memberof | Sort-Object
        }
        $ADObject | Format-ListCustom -Sort -PropertiesColor Green -PropertiesValuesToColor @(
            @{Property = "adspath" ; Pattern = $sPathRegex ; Color = $HighlightColor ; ColorGroups = @("val") ; AllMatches = $true}
            @{Property = "memberof" ; Pattern = $sDNRegex ; Color = $HighlightColor ; ColorGroups = @("val") ; AllMatches = $true}
            @{Property = "Path" ; Pattern = $sPathRegex ; Color = $HighlightColor ; ColorGroups = @("val") ; AllMatches = $true}
            @{Property = "manager" ; Pattern = $sPathRegex ; Color = $HighlightColor ; ColorGroups = @("val") ; AllMatches = $true}
            @{Property = "distinguishedname" ; Pattern = $sDNRegex ; Color = $HighlightColor ; ColorGroups = @("val") ; AllMatches = $true}
            @{Property = "directreports" ; Pattern = $sDNRegex ; Color = $HighlightColor ; ColorGroups = @("val") ; AllMatches = $true}
        )
    }
}
