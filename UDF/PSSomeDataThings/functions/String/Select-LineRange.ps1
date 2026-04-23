function Select-LineRange {
    <#
    .SYNOPSIS
        Selects a range of lines from a string array using regex delimiters

    .DESCRIPTION
        Extracts a subset of lines from a string array using regex patterns to identify
        the start and end boundaries. At least one of StartRegex or EndRegex must be provided.
        If StartRegex is empty, extraction starts from the first line.
        If EndRegex is empty, extraction continues to the last line.

    .PARAMETER InputArray
        The string array to search through.

    .PARAMETER StartRegex
        Regex pattern to identify the first line to extract. Optional.

    .PARAMETER EndRegex
        Regex pattern to identify the last line to extract. Optional.

    .PARAMETER FromEnd
        If specified, searches the array from end to start to optimize lookups near the end.

    .PARAMETER IncludeStartLine
        Whether to include the line matching StartRegex in the result. Defaults to $true.

    .PARAMETER IncludeEndLine
        Whether to include the line matching EndRegex in the result. Defaults to $true.

    .OUTPUTS
        System.String[]. The selected range of lines.

    .EXAMPLE
        $output = @("Start", "Data1", "Data2", "End")
        Select-LineRange -InputArray $output -StartRegex "Start" -EndRegex "End"

    .EXAMPLE
        # Without start regex (begins at first line)
        Select-LineRange -InputArray $output -EndRegex "ERROR"

    .EXAMPLE
        # Optimized search from end of array
        Select-LineRange -InputArray $output -StartRegex "Final" -EndRegex "Complete" -FromEnd

    .NOTES
        Author  : Loïc Ade
        Version : 1.1.0

        1.1.0 - 2026-04-20 - Loïc Ade
            - Added pipeline support (ValueFromPipeline on InputArray)

        1.0.0 
            - Initial version
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [string[]]$InputArray,

        [Parameter(Mandatory = $false)]
        [switch]$FromEnd,

        [Parameter(Mandatory = $false)]
        [string]$StartRegex = "",

        [Parameter(Mandatory = $false)]
        [string]$EndRegex = "",

        [Parameter(Mandatory = $false)]
        [bool]$IncludeStartLine = $true,

        [Parameter(Mandatory = $false)]
        [bool]$IncludeEndLine = $true
    )

    Begin {
        $aAccumulated = [System.Collections.Generic.List[string]]::new()
    }

    Process {
        foreach ($sLine in $InputArray) {
            $aAccumulated.Add($sLine)
        }
    }

    End {
        $InputArray = $aAccumulated.ToArray()

        # Parameter validation
        if ([string]::IsNullOrWhiteSpace($StartRegex) -and [string]::IsNullOrWhiteSpace($EndRegex)) {
            throw "At least one of StartRegex or EndRegex must be provided"
        }

        if ($InputArray.Count -eq 0) {
            Write-Warning "Input array is empty"
            return @()
        }

        # Determine start index
        $startIndex = 0

        if (-not [string]::IsNullOrWhiteSpace($StartRegex)) {
            if ($FromEnd) {
                # Search from the end for StartRegex
                for ($i = $InputArray.Count - 1; $i -ge 0; $i--) {
                    if ($InputArray[$i] -match $StartRegex) {
                        $startIndex = $i
                        if (-not $IncludeStartLine) {
                            $startIndex++
                        }
                        break
                    }
                }

                # No line matched StartRegex
                if ($i -lt 0) {
                    Write-Warning "No line matches the start regex: '$StartRegex'"
                    return @()
                }
            } else {
                # Normal search from the start for StartRegex
                for ($i = 0; $i -lt $InputArray.Count; $i++) {
                    if ($InputArray[$i] -match $StartRegex) {
                        $startIndex = $i
                        if (-not $IncludeStartLine) {
                            $startIndex++
                        }
                        break
                    }
                }

                # No line matched StartRegex
                if ($i -eq $InputArray.Count) {
                    Write-Warning "No line matches the start regex: '$StartRegex'"
                    return @()
                }
            }
        }

        # Determine end index
        $endIndex = $InputArray.Count - 1  # Defaults to the last line

        if (-not [string]::IsNullOrWhiteSpace($EndRegex)) {
            $foundEnd = $false
            if ($FromEnd) {
                # Search from the end for EndRegex
                for ($i = $InputArray.Count - 1; $i -ge $startIndex; $i--) {
                    if ($InputArray[$i] -match $EndRegex) {
                        $endIndex = $i
                        if (-not $IncludeEndLine) {
                            $endIndex--
                        }
                        $foundEnd = $true
                        break
                    }
                }
            } else {
                # Normal search from startIndex for EndRegex
                for ($i = $startIndex; $i -lt $InputArray.Count; $i++) {
                    if ($InputArray[$i] -match $EndRegex) {
                        $endIndex = $i
                        if (-not $IncludeEndLine) {
                            $endIndex--
                        }
                        $foundEnd = $true
                        break
                    }
                }
            }

            # No line matched EndRegex
            if (-not $foundEnd) {
                Write-Warning "No line matches the end regex: '$EndRegex'"
                return @()
            }
        }

        # Index validation
        if ($startIndex -gt $endIndex) {
            Write-Warning "Start index ($startIndex) is greater than end index ($endIndex)"
            return @()
        }

        # Extract the lines
        $result = @()
        for ($i = $startIndex; $i -le $endIndex; $i++) {
            $result += $InputArray[$i]
        }

        return $result
    }
}
