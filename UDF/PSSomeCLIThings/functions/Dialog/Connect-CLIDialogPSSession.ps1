function Connect-CLIDialogPSSession {
    <#
    .SYNOPSIS
        Connects to a remote computer via PSSession with an interactive credential dialog.

    .DESCRIPTION
        Prompts the user for credentials via Read-CLIDialogCredential, then creates a PSSession
        to the specified computer. If the connection fails, the user is prompted to retry with
        different credentials. Supports Cancel and Back actions for workflow integration.

    .PARAMETER ComputerName
        The name of the remote computer to connect to. Mandatory.

    .PARAMETER Credential
        An existing PSCredential object to reuse. If provided, the user will be offered
        to keep or replace the existing credentials.

    .PARAMETER Session
        An existing PSSession object. If provided and still open to the same computer,
        it is returned immediately without prompting.

    .PARAMETER Message
        The message displayed in the credential dialog. Default: "Please provide credentials to connect to"

    .PARAMETER ErrorMessage
        The message displayed when the connection fails. Default: "Connection failed. Please try again."

    .PARAMETER ErrorColor
        The color of the error message. Default: from theme ErrorColor.

    .PARAMETER AllowCancel
        Switch parameter. Adds a Cancel button to the credential dialog.

    .PARAMETER AllowBack
        Switch parameter. Adds a Back button to the credential dialog.

    .OUTPUTS
        Returns a hashtable with:
        - Credential: the PSCredential used
        - Session: the opened PSSession
        Or a DialogResult.Action.Cancel if the user cancels.
        Or a DialogResult.Action.Back if the user presses Back.

    .EXAMPLE
        $result = Connect-CLIDialogPSSession -ComputerName "Server01"
        if ($result -and -not $result.PSTypeNames[0] -like "DialogResult.Action.*") {
            Invoke-Command -Session $result.Session -ScriptBlock { hostname }
        }

    .EXAMPLE
        $result = Connect-CLIDialogPSSession -ComputerName "Server01" -Credential $cred -Session $session
        # Reuses existing session if still open, otherwise prompts for credentials

    .NOTES
        Author: Loïc Ade
        Version: 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-04-06 - Loïc Ade
            - Initial release
            - Interactive credential prompt with retry on failure
            - Reuse of existing PSSession if still open
            - Cancel and Back support
            - Error message on connection failure with retry
    #>
    Param(
        [Parameter(Mandatory)]
        [string]$ComputerName,
        [pscredential]$Credential,
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$Message = "Please provide credentials to connect to",
        [string]$ErrorMessage = "Connection failed. Please try again.",
        [System.ConsoleColor]$ErrorColor = (Get-CLIDialogTheme "ErrorColor"),
        [switch]$AllowCancel,
        [switch]$AllowBack
    )

    # Reuse existing session if still open to the same computer
    if ($Session -and ($Session.State -eq "Opened") -and ($Session.ComputerName -eq $ComputerName)) {
        return @{
            Credential = $Credential
            Session = $Session
        }
    }

    while ($true) {
        # Prompt for credentials
        $hCredParams = @{
            Message = "$Message $ComputerName"
            AddCancel = $AllowCancel
            AddBack = $AllowBack
            ReturnDialogResult = $true
        }
        if ($Credential) {
            $hCredParams.Credential = $Credential
        }
        $oCredResult = Read-CLIDialogCredential @hCredParams

        # Handle Cancel or Back — return the DialogResult
        if ($null -eq $oCredResult) {
            return New-DialogResultAction -Action "Cancel"
        }
        if ($oCredResult.PSTypeNames -and $oCredResult.PSTypeNames[0] -like "DialogResult.Action.*") {
            return $oCredResult
        }

        $Credential = $oCredResult

        # Try to connect
        try {
            $oSession = New-PSSession -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop
            return @{
                Credential = $Credential
                Session = $oSession
            }
        } catch {
            Write-Host "$ErrorMessage $($_.Exception.TransportMessage)" -ForegroundColor $ErrorColor
            # On credential-related failures, clear credentials to force new prompt
            # 5    = ERROR_ACCESS_DENIED
            # 1326 = ERROR_LOGON_FAILURE (bad user/password)
            # 1330 = ERROR_PASSWORD_EXPIRED
            if ($_.Exception.ErrorCode -in @(5, 1326, 1330)) {
                $Credential = $null
            }
        }
    }
}
