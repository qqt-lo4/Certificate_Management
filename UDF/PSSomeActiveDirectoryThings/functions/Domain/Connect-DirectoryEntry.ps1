function Connect-DirectoryEntry {
    <#
    .SYNOPSIS
        Connects to an Active Directory server using DirectoryEntry

    .DESCRIPTION
        Creates a DirectoryEntry connection to the specified AD server.
        Optionally uses provided credentials for authentication.

    .PARAMETER Server
        The AD server or LDAP path to connect to.

    .PARAMETER Credential
        Optional PSCredential for authentication.

    .OUTPUTS
        System.DirectoryServices.DirectoryEntry. The connected directory entry.

    .EXAMPLE
        $c = Get-Credential
        $de = Connect-DirectoryEntry -Server lan.example.com -Credential $c

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
        Version 1.0: First version
    #>
    
    Param(
        [Parameter(Mandatory)]
        [string]$Server,
        [AllowNull()]
        [pscredential]$Credential
    )
    [System.DirectoryServices.DirectoryEntry] $de = if ($Credential) {
        $sUsername = $Credential.UserName
        $sUnsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password))
        New-Object System.DirectoryServices.DirectoryEntry($Server, $sUsername, $sUnsecurePassword)
    } else {
        New-Object System.DirectoryServices.DirectoryEntry($Server)
    }
    return $de
}
