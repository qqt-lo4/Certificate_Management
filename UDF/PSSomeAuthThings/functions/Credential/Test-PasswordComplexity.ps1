function Test-PasswordComplexity {
    <#
    .SYNOPSIS
        Tests a password against a complexity policy

    .DESCRIPTION
        Validates a password (string or SecureString) against a password policy object.
        Checks mandatory rules, common rules (with minimum count), and forbidden patterns.
        Returns success status and list of missing requirements.

    .PARAMETER Password
        The password to test (as string or SecureString).

    .PARAMETER Policy
        A password policy object (created by New-PasswordPolicy). If not provided, uses
        default policy (all common rules with min 3, min length 10).

    .OUTPUTS
        [hashtable]. Object with Success (bool) and MissingRequirements (array) properties.

    .EXAMPLE
        $policy = New-PasswordPolicy -All -MinimalLength 12
        $result = Test-PasswordComplexity -Password $securePass -Policy $policy
        if (-not $result.Success) {
            Write-Host "Password validation failed: $($result.MissingRequirements -join ', ')"
        }

    .EXAMPLE
        Test-PasswordComplexity -Password "MyP@ssw0rd123"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$Password,
        [Parameter(Position = 1)]
        [object]$Policy = (New-PasswordPolicy -All -MustRespectCommonRulesCount 3 -MinimalLength 10)
    )
    Begin {
        $sPass = if ($Password -is [securestring]) {
            [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
        } elseif ($Password -is [string]) {
            $Password
        } else {
            throw [System.ArgumentException] "Can't convert `$Password to a supprted type"
        }
    }
    Process {
        $bMandatoryRulesSuccess = $true
        $aPasswordComplexityReasons = @()
        foreach ($regex in $Policy.MandatoryRules.Keys) {
            if ($sPass -cnotmatch $regex) {
                $bMandatoryRulesSuccess = $false
                $aPasswordComplexityReasons += $Policy.MandatoryRules[$regex]
            }
        }
        $iCommonRulesCount = 0
        $aMissingStandardRequirements = @()
        foreach ($regex in $Policy.CommonRules.Keys) {
            if ($sPass -cmatch $regex) {
                $iCommonRulesCount += 1
            } else {
                $aMissingStandardRequirements += $Policy.CommonRules[$regex]
            }
        }
        $bCommonRulesSuccess = ($iCommonRulesCount -ge $Policy.MinCommonRulesCount)
        if (-not $bCommonRulesSuccess) {
            $aPasswordComplexityReasons += if ($aMissingStandardRequirements.Count -eq 1) {
                "No " + $aMissingStandardRequirements
            } else {
                $missingItemCount = $Policy.MinCommonRulesCount - $iCommonRulesCount
                "$missingItemCount element$(if ($missingItemCount -ge 2) {"s"}) $(if ($missingItemCount -eq 1) {"is"} else {"are"}) missing among " + ($aMissingStandardRequirements -join ",")
            }
        }
        $bNoForbiddenMatches = $true
        foreach ($regex in $Policy.ForbiddenRules.Keys) {
            if ($sPass -cmatch $regex) {
                $bMandatoryRulesSuccess = $false
                $aPasswordComplexityReasons += $Policy.ForbiddenRules[$regex]
            }
        }
        $bSuccess = $bMandatoryRulesSuccess -and $bCommonRulesSuccess -and $bNoForbiddenMatches
        $hResult = [ordered]@{
            Success = $bSuccess
            MissingRequirements = $aPasswordComplexityReasons
        }
        return $hResult
    }
}
