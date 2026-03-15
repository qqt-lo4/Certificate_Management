function Read-ADObjectIdentity {
    <#
    .SYNOPSIS
        Reads and validates an AD object identity from input or user prompt

    .DESCRIPTION
        Parses a string to identify an AD object identity (username, DN, UPN, email,
        GUID, or SID). If no InputString is provided, prompts the user interactively
        until a valid identity format is entered.

    .PARAMETER InputString
        The string to parse as an AD object identity. If omitted, prompts the user.

    .PARAMETER HeaderQuestion
        The prompt message displayed when asking the user for input.

    .PARAMETER ErrorMessage
        The error message displayed when the user enters an invalid format.

    .PARAMETER DomainRegex
        Regex pattern for matching domain names.

    .PARAMETER UsernameRegex
        Regex pattern for matching usernames.

    .PARAMETER DNRegex
        Regex pattern for matching distinguished names.

    .PARAMETER GUIDRegex
        Regex pattern for matching GUIDs.

    .PARAMETER SIDRegex
        Regex pattern for matching SIDs.

    .OUTPUTS
        [hashtable] or $null. A hashtable with the identity type and value, or $null if no match.

    .EXAMPLE
        $identity = Read-ADObjectIdentity -InputString "DOMAIN\jdoe"

    .EXAMPLE
        $identity = Read-ADObjectIdentity
        # Prompts the user interactively

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [string]$InputString,
        [string]$HeaderQuestion = "Please enter an AD object name, DN, UPN ou email",
        [string]$ErrorMessage = "Bad format, please enter a supported format",
        [string]$DomainRegex = "(?<domain>[A-Za-z._0-9-]+)",
        [string]$UsernameRegex = "(?<user>[\p{L}\p{Pc}\p{Pd}\p{Nd} .*]+)",
        [string]$DNRegex = "(?<dn>.+,((dc|DC)=[^,]+))",
        [string]$GUIDRegex = "(?<guid>[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12})",
        [string]$SIDRegex = "(?<sid>S-1-[0-59]-\d{2}-\d{8,10}-\d{8,10}-\d{8,10}-[1-9]\d{3})"
    )
    Begin {
        $hTestOnceCommonParams = @{
            DomainRegex = $DomainRegex 
            UsernameRegex = $UsernameRegex 
            DNRegex = $DNRegex
            GUIDRegex = $GUIDRegex
            SIDRegex = $SIDRegex
        }
    }
    Process {
        if ($InputString) {
            return Test-StringIsADObjectIdentity -InputString $InputString @hTestOnceCommonParams
        } else {
            while ($true) {
                $sTypedValue = Read-Host -Prompt $HeaderQuestion
                $hTestOnce = Test-StringIsADObjectIdentity -InputString $sTypedValue @hTestOnceCommonParams
                if ($hTestOnce -ne $null) {
                    return $hTestOnce
                } else {
                    Write-Host $ErrorMessage -ForegroundColor Red
                }
            }    
        }
    }
}
