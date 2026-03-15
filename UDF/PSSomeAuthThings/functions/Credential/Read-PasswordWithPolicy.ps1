function Read-PasswordWithPolicy {
    <#
    .SYNOPSIS
        Prompts for a password while validating it against a policy

    .DESCRIPTION
        Interactively prompts the user to enter a password and validates it against
        a password policy. Loops until a valid password is entered or an empty
        password is confirmed (if allowed). Displays missing requirements on validation
        failure.

    .PARAMETER Prompt
        The prompt message to display when requesting the password.

    .PARAMETER Policy
        A password policy object (created by New-PasswordPolicy) to validate against.

    .PARAMETER AllowEmpty
        If specified, allows empty passwords.

    .PARAMETER ConfirmEmpty
        If specified (and AllowEmpty is set), prompts for confirmation when an empty password is entered.

    .OUTPUTS
        [SecureString]. The validated password.

    .EXAMPLE
        $policy = New-PasswordPolicy -All -MinimalLength 12
        $pass = Read-PasswordWithPolicy -Prompt "Enter password" -Policy $policy

    .EXAMPLE
        $pass = Read-PasswordWithPolicy -Prompt "Private key password" -Policy $policy -AllowEmpty -ConfirmEmpty

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Prompt,
        [Parameter(Mandatory, Position = 1)]
        [object]$Policy,
        [switch]$AllowEmpty,
        [switch]$ConfirmEmpty
    )
    $bPasswordOK = $false
    $ssPwd = Read-Host -Prompt $Prompt -AsSecureString
    while ($bPasswordOK -eq $false) {
        $oTest = Test-PasswordComplexity -Password $ssPwd
        if ($AllowEmpty.IsPresent -and ($ssPwd.Length -eq 0)) {
            if ($ConfirmEmpty.IsPresent) {
                $oAnswer = Read-YesNoAnswer -headerQuestion "The entered password is empty. Do you confirm the private key will not be protected [y/N]?" -allowEmpty -valueIfEmpty "No"
                if ($oAnswer -eq "No") {
                    $ssPwd = Read-Host -Prompt $MessageBefore -AsSecureString
                } else {
                    $bPasswordOK = $true
                }
            } else {
                $bPasswordOK = $true
            }
        } else {
            if ($oTest.Success) {
                $bPasswordOK = $true
            } else {
                Write-Host "The password does not comply with the policy"
                Write-Host ("Reasons: " + ($oTest.MissingRequirements -join ","))
                $ssPwd = Read-Host -Prompt $MessageBefore -AsSecureString
            }    
        }
    }
    return $ssPwd
}
