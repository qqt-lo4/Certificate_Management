function Read-NewPassword {
    <#
    .SYNOPSIS
        Prompts for a new password with confirmation

    .DESCRIPTION
        Interactively prompts the user to enter a new password twice for confirmation.
        Validates both entries match and optionally enforces a password policy.
        Loops until both passwords match.

    .PARAMETER HeaderQuestion
        The prompt message for the first password entry. Default: "Please type password".

    .PARAMETER RepeatQuestion
        The prompt message for the password confirmation. Default: "Please type again your password".

    .PARAMETER ErrorPwdNotEquals
        The error message displayed when passwords don't match. Default: "Both passwords are not the same, please try again".

    .PARAMETER Policy
        A password policy object (created by New-PasswordPolicy). If provided, validates the first password against the policy.

    .PARAMETER AllowEmpty
        If specified, allows empty passwords.

    .OUTPUTS
        [SecureString]. The validated password.

    .EXAMPLE
        $pass = Read-NewPassword

    .EXAMPLE
        $policy = New-PasswordPolicy -All -MinimalLength 12
        $pass = Read-NewPassword -Policy $policy -HeaderQuestion "Enter new admin password"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [string]$HeaderQuestion = "Please type password",
        [string]$RepeatQuestion = "Please type again your password",
        [string]$ErrorPwdNotEquals = "Both passwords are not the same, please try again",
        [object]$Policy,
        [switch]$AllowEmpty
    )
    $bBothEquals = $false
    while ($bBothEquals -eq $false) {
        $sPwd1 = if ($Policy) {
            Read-PasswordWithPolicy -Prompt $HeaderQuestion -Policy $Policy
        } else {
            Read-Host -Prompt $HeaderQuestion -AsSecureString
        }
        $sPwd2 = Read-Host -Prompt $RepeatQuestion -AsSecureString
        if ($null -eq $sPwd1) { $sPwd1 = "" }
        if ($null -eq $sPwd2) { $sPwd2 = "" }
        $bBothEquals = ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sPwd1))) `
                    -eq ([Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sPwd2)))
        if (-not $bBothEquals) {
            Write-Host $ErrorPwdNotEquals
        }
    }
    return $sPwd1    
}
