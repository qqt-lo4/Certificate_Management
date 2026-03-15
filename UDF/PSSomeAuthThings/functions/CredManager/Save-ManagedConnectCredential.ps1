function Save-ManagedConnectCredential {
    <#
    .SYNOPSIS
        Saves connection credentials to Windows Credential Manager

    .DESCRIPTION
        Stores credentials for a connection target using a naming convention:
        - {target}_user: stores the username and password
        - {target}_connect: stores connection parameters (connect1, connect2)
        - {target}_options: stores additional connection options as key-value pairs

    .PARAMETER target
        The target name prefix for the credential set.

    .PARAMETER connect1
        First connection parameter (e.g., hostname, address).

    .PARAMETER connect2
        Second connection parameter (e.g., port, database name).

    .PARAMETER credential
        A PSCredential object with username and password.

    .PARAMETER options
        A hashtable of additional connection options to store.

    .OUTPUTS
        None.

    .EXAMPLE
        $cred = Get-Credential
        Save-ManagedConnectCredential -target "MyServer" -connect1 "192.168.1.10" -connect2 "4343" -credential $cred

    .EXAMPLE
        $opts = @{ SSL = "true"; Timeout = "30" }
        Save-ManagedConnectCredential -target "API" -connect1 "api.example.com" -connect2 "443" -credential $cred -options $opts

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$target,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$connect1,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$connect2,
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [pscredential]$credential,
        [hashtable]$options
    )
    Add-ManagedCredential -resource $($target + "_user") -username $credential.UserName -Password $credential.GetNetworkCredential().Password
    Add-ManagedCredential -resource $($target + "_connect") -username $connect1 -Password $connect2
    foreach ($key in $options.Keys) {
        Add-ManagedCredential -resource $($target + "_options") -username $key -Password $options[$key]
    }
}