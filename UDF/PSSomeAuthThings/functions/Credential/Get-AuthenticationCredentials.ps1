function Get-AuthenticationCredentials {
    <#
    .SYNOPSIS
        Retrieves authentication credentials based on the mode used

    .DESCRIPTION
        Standardizes credential retrieval for different authentication modes:
        - userpasswd: Username and Password provided directly
        - passwdfile: Username and encrypted password file
        - credential: PSCredential object

    .PARAMETER Username
        The username (for userpasswd and passwdfile modes).

    .PARAMETER Password
        The password as a SecureString (for userpasswd mode).

    .PARAMETER EncryptedPasswordFile
        The path to an encrypted password file (for passwdfile mode).

    .PARAMETER Credential
        A PSCredential object (for credential mode).

    .OUTPUTS
        [PSCustomObject]. Object with Username and Password (SecureString) properties.

    .EXAMPLE
        $auth = Get-AuthenticationCredentials -Username "user" -Password $securePass

    .EXAMPLE
        $auth = Get-AuthenticationCredentials -Username "user" -EncryptedPasswordFile "C:\pass.txt"

    .EXAMPLE
        $auth = Get-AuthenticationCredentials -Credential $cred

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    
    param(
        [string]$Username,
        [securestring]$Password,
        [string]$EncryptedPasswordFile,
        [pscredential]$Credential
    )
    
    try {
        # Automatic determination of authentication mode
        if ($Credential) {
            # Credential mode
            return [PSCustomObject]@{
                Username = $Credential.UserName
                Password = $Credential.Password
            }
        }
        elseif ($Username -and $Password) {
            # Userpasswd mode
            return [PSCustomObject]@{
                Username = $Username
                Password = $Password
            }
        }
        elseif ($Username -and $EncryptedPasswordFile) {
            # Passwdfile mode
            if (-not (Test-Path $EncryptedPasswordFile)) {
                throw "Password file not found: $EncryptedPasswordFile"
            }
            
            $encryptedPassword = Get-Content $EncryptedPasswordFile | ConvertTo-SecureString
            
            return [PSCustomObject]@{
                Username = $Username
                Password = $encryptedPassword
            }
        }
        else {
            throw "No valid authentication mode detected. Check the provided parameters."
        }
    }
    catch {
        throw "Error retrieving credentials: $($_.Exception.Message)"
    }
}
