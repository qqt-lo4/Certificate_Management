function Format-CustomHeaderTable {
    <#
    .SYNOPSIS
        Formats objects as a table with a custom-colored and optionally underlined header row.

    .DESCRIPTION
        Pipes objects through Format-Table, parses the output to identify header words
        using regex against the dash-underline row, applies Set-StringUnderline to each
        header word, and writes the header in color with Write-Host followed by the data
        rows via Out-Host.

        Requires the PSSomeDataThings module (provides Remove-EmptyString).

    .PARAMETER Content
        The objects to display as a table. Accepts pipeline input.

    .PARAMETER HeaderColor
        Color for the header row. Defaults to the current console foreground color.

    .PARAMETER DontUnderline
        Switch to disable underlining of header words.

    .OUTPUTS
        Formatted table output to the console with colored/underlined header.

    .EXAMPLE
        Get-Process | Select-Object Name, Id, CPU | Format-CustomHeaderTable -HeaderColor Cyan

        Displays processes in a table with a cyan underlined header.

    .EXAMPLE
        Get-Service | Format-CustomHeaderTable -DontUnderline

        Displays services in a table with colored header but no underline.

    .NOTES
        Author  : Loïc Ade
        Version : 1.1.0

        External dependencies: PSSomeDataThings (Remove-EmptyString)

        1.1.0 - 2026-04-19 - Loïc Ade
            - Added runtime check for PSSomeDataThings module availability
            - HeaderColor default now resolves from the current CLI dialog theme (Get-CLIDialogTheme)
            
        1.0.0 - Loïc Ade
            - Initial release
    #>
    Param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [object]$Content,
        [System.ConsoleColor]$HeaderColor = (Get-CLIDialogTheme "TableHeaderForegroundColor"),
        [switch]$DontUnderline
    )
    Begin {
        if (-not (Get-Module -Name PSSomeDataThings) -and -not (Get-Module -ListAvailable -Name PSSomeDataThings)) {
            throw "Format-CustomHeaderTable requires the PSSomeDataThings module (provides Remove-EmptyString). Please install or import it before calling this function."
        }
        $aContent = @()
    }
    Process {
        $aContent += $Content
    }
    End {
        if ($aContent) {
            $aFormatedTable = $aContent | Format-Table | Out-String 
            $aFormatedTable = $aFormatedTable | Remove-EmptyString
            $sRegex = "(?<twowordsseparated>- -)|(?<wordstart> -)|(?<endofword>- )|(?<endofword>-`r`n)|(?<endofword>-`n)|(?<endofword>-$)"
            $aHeader = $aFormatedTable[0..1]
            $ssSpace = Select-String -InputObject $aHeader[1] -Pattern $sRegex -AllMatches
            $aIndexes = @()
            if (($aHeader[1])[0] -eq "-") {
                $aIndexes += 0
            }
            $oSeparators = ($ssSpace.Matches.Groups | Where-Object { ($_.name -in @("twowordsseparated", "wordstart", "endofword")) -and ($_.Success -eq $true) })
            foreach ($item in $oSeparators) {
                switch ($item.Name) {
                    "endofword" {
                        $aIndexes += $item.Index
                    }
                    "wordstart" {
                        $aIndexes += ($item.Index + 1)
                    }
                    "twowordsseparated" {
                        $aIndexes += $item.Index
                        $aIndexes += ($item.Index + 2)
                    }
                }
            }
            $aHeaderWords = @()
            for ($i = 0; $i -lt $aIndexes.Count; $i += 2) {
                $aHeaderWords += ($aHeader[0])[$($aIndexes[$i])..$($aIndexes[$i + 1])] -join ""
            }
            $sHeaderLine = $aHeader[0]
            if (-not $DontUnderline) {
                foreach ($word in $aHeaderWords) {
                    $sHeaderLine = $sHeaderLine.Replace($word, ($word | Set-StringUnderline))
                }    
            }
            Write-Host $sHeaderLine -ForegroundColor $HeaderColor
            $iLastItem = $aContent.Count + 2
            $aFormatedTable[2..$iLastItem] | Out-Host
        }
    }
}
