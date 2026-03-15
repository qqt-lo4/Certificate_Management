function Get-DirectoryEntry {
    <#
    .SYNOPSIS
        Creates a DirectoryEntry object with optional credentials

    .DESCRIPTION
        Creates a System.DirectoryServices.DirectoryEntry for the specified LDAP path,
        optionally using provided credentials and authentication type.

    .PARAMETER Path
        The LDAP path to connect to.

    .PARAMETER Credential
        Optional PSCredential for authentication.

    .PARAMETER AuthenticationType
        Optional authentication type flags.

    .OUTPUTS
        System.DirectoryServices.DirectoryEntry.

    .EXAMPLE
        $de = Get-DirectoryEntry -Path "LDAP://DC=contoso,DC=com"

    .EXAMPLE
        $de = Get-DirectoryEntry -Path "LDAP://DC=contoso,DC=com" -Credential $cred

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Path,
        [pscredential]$Credential,
        [System.DirectoryServices.AuthenticationTypes]$AuthenticationType
    )
    $aDE = @($Path)
    if ($Credential) {
        $sUsername = $Credential.UserName
        $sPassword = $credential.GetNetworkCredential().password
        $aDE += $sUsername
        $aDE += $sPassword
        if ($AuthenticationType) {
            $aDE += $AuthenticationType
        }
    }
    return New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $aDE
}
