function Add-ManagedCredential {
    <#
    .SYNOPSIS
        Adds a credential to the Windows Credential Manager

    .DESCRIPTION
        Stores a credential in the Windows Password Vault (Credential Manager) associated
        with a specified resource. Accepts either a PSCredential object or username/password
        separately.

    .PARAMETER resource
        The resource name the credential applies to (e.g., "MyApp", "https://api.example.com").

    .PARAMETER username
        The username to store (when not using -credential parameter).

    .PARAMETER Password
        The password as a plain-text string (when not using -credential parameter).

    .PARAMETER credential
        A PSCredential object to store.

    .OUTPUTS
        None.

    .EXAMPLE
        Add-ManagedCredential -resource "MyApp" -username "admin" -Password "P@ssw0rd"

    .EXAMPLE
        $cred = Get-Credential
        Add-ManagedCredential -resource "https://api.example.com" -credential $cred

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(
			HelpMessage	= "Enter the resource the credential applies to",
			Position = 0, Mandatory = $true, ParameterSetName = "cred"
	  	)]
        [Parameter(
			HelpMessage	= "Enter the resource the credential applies to",
			Position = 0, Mandatory = $true, ParameterSetName = "pwd"
	  	)]
        [ValidateNotNullOrEmpty()]
		[String[]]$resource,

        [Parameter(
			HelpMessage	= "Enter the user name(s) to add",
			Mandatory = $true, ParameterSetName = "pwd"
	  	)]
		[ValidateNotNullOrEmpty()]
		[Alias("UN","Name","AccountName")]
        [string]$username,

        [Parameter(
			HelpMessage	= "Enter the password for the user name",
			Mandatory = $true, ParameterSetName = "pwd"
	  	)]
		[ValidateNotNullOrEmpty()]
		[String]
        $Password,

        [Parameter(
			HelpMessage	= "Enter the credentials to save",
			Mandatory = $true, ParameterSetName = "cred"
	  	)]
		[ValidateNotNullOrEmpty()]
		[pscredential]
		$credential
    )

    if ($PsCmdlet.ParameterSetName -eq "cred") {
        $username = $credential.UserName
        $Password = $credential.GetNetworkCredential().Password
    }

    $vaultType = [Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
	$vault     = new-object Windows.Security.Credentials.PasswordVault
    $vault.Add($(new-object Windows.Security.Credentials.PasswordCredential $resource,$username,$Password))
}