function Get-AllManagedCredentials {
    <#
    .SYNOPSIS
        Retrieves all credentials from the Windows Credential Manager

    .DESCRIPTION
        Fetches all stored credentials from the Windows Password Vault (Credential Manager).
        Optionally retrieves the passwords (decrypted) for each credential.

    .PARAMETER retrievepasswords
        If true (default), retrieves and decrypts the passwords for all credentials.

    .OUTPUTS
        [Windows.Security.Credentials.PasswordCredential[]]. Array of credential objects.

    .EXAMPLE
        Get-AllManagedCredentials

    .EXAMPLE
        $creds = Get-AllManagedCredentials -retrievepasswords $false
        $creds | Format-Table Resource, UserName

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    [OutputType([Windows.Security.Credentials.PasswordCredential])]
    Param(
        [boolean]$retrievepasswords = $true
    )
    $vaultType = [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
	$vault     = new-object Windows.Security.Credentials.PasswordVault
    $result = $vault.RetrieveAll()
    if ($retrievepasswords) {
        foreach ($item in $result) {
            $item.RetrievePassword()
        }    
    }
    return $result
}