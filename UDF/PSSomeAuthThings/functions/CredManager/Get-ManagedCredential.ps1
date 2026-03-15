function Get-ManagedCredential {
    <#
    .SYNOPSIS
        Retrieves credentials for a specific resource from Windows Credential Manager

    .DESCRIPTION
        Fetches all stored credentials associated with a specific resource name from
        the Windows Password Vault (Credential Manager). Optionally retrieves the
        passwords (decrypted) for each credential.

    .PARAMETER ressource
        The resource name to search for.

    .PARAMETER retrievepasswords
        If true (default), retrieves and decrypts the passwords for all credentials.

    .OUTPUTS
        [Windows.Security.Credentials.PasswordCredential[]]. Array of credential objects for the resource.

    .EXAMPLE
        Get-ManagedCredential -ressource "MyApp"

    .EXAMPLE
        $creds = Get-ManagedCredential -ressource "https://api.example.com" -retrievepasswords $false

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    [OutputType([Windows.Security.Credentials.PasswordCredential])]
    Param(
        [string]$ressource,
        [boolean]$retrievepasswords = $true
    )
    [Windows.Security.Credentials.PasswordVault]$vault = new-object Windows.Security.Credentials.PasswordVault -ErrorAction silentlycontinue
    $result = $vault.FindAllByResource($ressource)
    if ($retrievepasswords) {
        foreach ($item in $result) {
            $item.RetrievePassword()
        }    
    }
    return $result
}
