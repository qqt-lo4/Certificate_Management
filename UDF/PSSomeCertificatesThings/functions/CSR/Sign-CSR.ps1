function Sign-CSR {
    <#
    .SYNOPSIS
        Signs a Certificate Signing Request using a Certificate Authority

    .DESCRIPTION
        Resubmits a pending certificate request to a Windows Certificate Authority for signing.
        Uses certutil -resubmit to approve and issue a previously submitted request.
        Supports remote execution via PSSession.

    .PARAMETER Session
        PSSession to execute the command remotely.

    .PARAMETER RequestID
        The Request ID of the pending CSR on the CA.

    .PARAMETER CAName
        Name of the Certificate Authority to use for signing.

    .OUTPUTS
        [PSCustomObject]. Object with Success (boolean), ExitCode (int), and Output (string array) properties.

    .EXAMPLE
        Sign-CSR -RequestID "123" -CAName "CompanyCA"

    .EXAMPLE
        $session = New-PSSession -ComputerName "CA-Server"
        Sign-CSR -Session $session -RequestID "456" -CAName "RootCA"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$RequestID,
        [string]$CAName
    )
    function Add-Quote {
        Param(
            [string]$Text
        )
        $result = if ($Text.Contains(" ")) { "`"$Text`"" } else { $Text }
        return $result
    }

    if ($ComputerName -or $Session) {
        return Invoke-ThisFunctionRemotely -ThisFunctionName $MyInvocation.InvocationName -ThisFunctionParameters $PSBoundParameters
    } else {
        $aCertUtilArgs += @("-config")
        $aCertUtilArgs += (Add-Quote ($(hostname) + "\" + $CAName))
        $aCertUtilArgs += "-resubmit"
        $aCertUtilArgs += $RequestID
        Write-Verbose ("certutil " + ($aCertUtilArgs -join " "))
        $output = $(certutil $aCertUtilArgs)
        $certreqSuccess = ($LastExitCode -eq 0)
        $iExitCode = $LastExitCode
        $hResult = [ordered]@{
            Success = $certreqSuccess
            ExitCode = $iExitCode
            Output = $output
        }
        return New-Object -TypeName psobject -Property $hResult
    }
}