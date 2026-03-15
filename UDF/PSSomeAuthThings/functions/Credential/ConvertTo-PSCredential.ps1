function ConvertTo-PSCredential {
    <#
    .SYNOPSIS
        Converts a username and plain-text password to a PSCredential object

    .DESCRIPTION
        Creates a System.Management.Automation.PSCredential object from a username
        and plain-text password string. The password is converted to a SecureString
        internally.

    .PARAMETER username
        The username for the credential.

    .PARAMETER password
        The plain-text password to convert.

    .OUTPUTS
        [PSCredential]. A PowerShell credential object.

    .EXAMPLE
        $cred = ConvertTo-PSCredential -username "admin" -password "P@ssw0rd"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [string]$username,
        [string]$password
    )
    return New-Object System.Management.Automation.PSCredential($username, `
                            $(ConvertTo-SecureString $password -AsPlainText -Force))
}