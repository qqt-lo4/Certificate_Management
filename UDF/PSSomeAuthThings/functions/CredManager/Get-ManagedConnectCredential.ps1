function Get-ManagedConnectCredential {
    <#
    .SYNOPSIS
        Retrieves connection credentials from Windows Credential Manager

    .DESCRIPTION
        Fetches credentials for a connection target using a naming convention:
        - {target}_user: username and password
        - {target}_connect: connection parameters (connect1, connect2)
        - {target}_options: additional connection options
        Returns an object with credential, connect1, connect2, and options properties.

    .PARAMETER target
        The target name prefix for the credential set.

    .OUTPUTS
        [PSCustomObject]. Object with credential (PSCredential), connect1, connect2, and options (hashtable) properties.

    .EXAMPLE
        $conn = Get-ManagedConnectCredential -target "MyServer"
        # Retrieves credentials from MyServer_user, MyServer_connect, MyServer_options

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [string]$target
    )
    $cred = Get-AllManagedCredentials | ForEach-Object {
                    if (($_.Resource -match $("^" + $target + "_connect$")) `
                    -or ($_.Resource -match $("^" + $target + "_user$")) `
                    -or ($_.Resource -match $("^" + $target + "_options$"))) {
                        $_
                    }
                }
    if (($null -eq $cred) -or ($cred.Count -lt 2)) {
        throw [System.InvalidOperationException] "This target does not have a user or a connection info"
    }
    $user = $cred | Where-Object { $_.Resource -eq $($target + "_user") } | Select-Object -ExpandProperty "UserName"
    $password = $cred | Where-Object { $_.Resource -eq $($target + "_user") } | Select-Object -ExpandProperty "Password"
    $connect1 = $cred | Where-Object { $_.Resource -eq $($target + "_connect") } | Select-Object -ExpandProperty "UserName"
    $connect2 = $cred | Where-Object { $_.Resource -eq $($target + "_connect") } | Select-Object -ExpandProperty "Password"
    $opt = @{}
    $cred | Where-Object { $_.Resource -eq $($target + "_options") } `
                        | ForEach-Object { $opt.Add($_.UserName, $_.Password) } | Out-Null
    $credential = New-Object System.Management.Automation.PSCredential($user, `
                                    $(ConvertTo-SecureString $password -AsPlainText -Force))
    return New-Object PSObject -Property @{
        credential=$credential
        connect1=$connect1
        connect2=$connect2
        options=$opt
    }
}