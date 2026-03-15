# function Send-CSRToCA {
#     <#
#     .SYNOPSIS
#         Submits a Certificate Signing Request to a Certificate Authority

#     .DESCRIPTION
#         Sends a CSR file to a Windows Certificate Authority using certreq -Submit.
#         Optionally specifies a certificate template and retrieves the Request ID.
#         Supports remote execution via PSSession.

#     .PARAMETER Session
#         PSSession to execute the command remotely.

#     .PARAMETER CSRPath
#         Path to the CSR file to submit.

#     .PARAMETER OutputCerPath
#         Output path for the certificate file (if immediately issued).

#     .PARAMETER PKIServer
#         Name of the PKI server hosting the CA.

#     .PARAMETER CAName
#         Name of the Certificate Authority.

#     .PARAMETER TemplateName
#         Certificate template name to use for the request.

#     .PARAMETER DontRemoveCSR
#         If specified, the CSR file will not be deleted after submission.

#     .OUTPUTS
#         [PSCustomObject]. Object with Success (boolean), RequestID (int), ExitCode (int), and Output (string array) properties.

#     .EXAMPLE
#         Send-CSRToCA -CSRPath "C:\Temp\cert.req" -PKIServer "PKI-Server" -CAName "CompanyCA"

#     .EXAMPLE
#         Send-CSRToCA -CSRPath "C:\Temp\cert.req" -PKIServer "PKI-Server" -CAName "CompanyCA" -TemplateName "WebServer" -OutputCerPath "C:\Certs\cert.cer"

#     .EXAMPLE
#         $session = New-PSSession -ComputerName "CA-Server"
#         Send-CSRToCA -Session $session -CSRPath "request.csr" -PKIServer "PKI-Server" -CAName "RootCA" -DontRemoveCSR

#     .NOTES
#         Author  : Loïc Ade
#         Version : 1.0.0
#     #>
#     [CmdletBinding()]
#     Param(
#         [System.Management.Automation.Runspaces.PSSession]$Session,
#         [Parameter(Mandatory)]
#         [string]$CSRPath,
#         [string]$OutputCerPath,
#         [Parameter(Mandatory)]
#         [string]$PKIServer,
#         [Parameter(Mandatory)]
#         [string]$CAName,
#         [string]$TemplateName,
#         [switch]$DontRemoveCSR
#     )

#     function Add-Quote {
#         Param(
#             [string]$Text
#         )
#         $result = if ($Text.Contains(" ")) { "`"$Text`"" } else { $Text }
#         return $result
#     }

#     if ($ComputerName -or $Session) {
#         return Invoke-ThisFunctionRemotely -ThisFunctionName $MyInvocation.InvocationName -ThisFunctionParameters $PSBoundParameters
#     } else {
#         $aCertReqArgs = @("-Submit")
#         $aCertReqArgs += "-q"
#         $aCertReqArgs += "-v"
#         if ($TemplateName) {
#             $aCertReqArgs += "-attrib"
#             $aCertReqArgs += ("CertificateTemplate:" + $TemplateName)
#         }
#         $aCertReqArgs += "-config"
#         $aCertReqArgs += (Add-Quote ($(hostname) + "\" + $CAName))
#         $aCertReqArgs +=  (Add-Quote $CSRPath)
#         if ($OutputCerPath) {
#             $aCertReqArgs += (Add-Quote $OutputCerPath)
#         }
#         Write-Verbose ("certreq " + ($aCertReqArgs -join " "))
#         $output = $(certreq $aCertReqArgs)
#         $certreqSuccess = ($LastExitCode -eq 0)
#         $iExitCode = $LastExitCode
#         $iRequestID = -1
#         $iRequestID = foreach($item in $output) {
#             if ($item -match "^RequestId: ?([0-9]+).*$") {
#                 [int]$Matches.1 
#             }
#         }
#         $hResult = [ordered]@{
#             Success = $certreqSuccess
#             RequestID = $iRequestID
#             ExitCode = $iExitCode
#             Output = $output
#         }
#         if (-not $DontRemoveCSR) {
#             Remove-Item -Path $CSRPath
#         }
#         return New-Object -TypeName psobject -Property $hResult
#     }
# }

function Send-CSRToCA {
    <#
    .SYNOPSIS
        Submits a Certificate Signing Request to a Certificate Authority

    .DESCRIPTION
        Sends a CSR to a Windows Certificate Authority using the ICertRequest2 COM interface.
        The CSR content is passed directly as a string, eliminating the need to copy files
        to the remote server. Supports local and remote execution via PSSession or ComputerName.

    .PARAMETER Session
        PSSession to execute the command remotely on the CA server.

    .PARAMETER ComputerName
        Name of the remote computer to execute the command on.

    .PARAMETER Credential
        Credentials for remote execution (used with ComputerName).

    .PARAMETER CSRContent
        Content of the CSR file as a Base64-encoded string (PEM format).

    .PARAMETER CAName
        Name of the Certificate Authority.

    .PARAMETER TemplateName
        Certificate template name to use for the request.

    .OUTPUTS
        [PSCustomObject] with properties:
            - Success     : [bool] True if disposition is Issued (3) or Pending (5)
            - RequestID   : [int] The request ID assigned by the CA
            - Disposition : [int] The disposition code (3=Issued, 5=Pending, etc.)

    .EXAMPLE
        $csrContent = Get-Content "C:\Temp\cert.req" -Raw
        Send-CSRToCA -CSRContent $csrContent -CAName "CompanyCA"

    .EXAMPLE
        $session = New-PSSession -ComputerName "CA-Server" -Credential $cred
        $csrContent = Get-Content "C:\Temp\cert.req" -Raw
        Send-CSRToCA -Session $session -CSRContent $csrContent -CAName "RootCA" -TemplateName "WebServer"

    .NOTES
        Author  : Loïc Ade
        Version : 2.0.0

        1.0.0 - Initial version using certreq command line with file copy
        2.0.0 (2026-03-14)
            - Uses ICertRequest2 COM interface instead of certreq
            - CSRContent parameter replaces CSRPath (no file copy needed)
            - Removed PKIServer parameter (uses $env:COMPUTERNAME on execution target)
            - Removed OutputCerPath and DontRemoveCSR parameters
            - Uses Split-RemoteAndNativeParameters with Invoke-Command splatting
    #>
    [CmdletBinding()]
    Param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ComputerName,
        [PSCredential]$Credential,
        [Parameter(Mandatory)]
        [string]$CSRContent,
        [Parameter(Mandatory)]
        [string]$CAName,
        [string]$TemplateName
    )

    $hSplitParams = Split-RemoteAndNativeParameters
    $hSplitParamsRemote = $hSplitParams.Remote

    return Invoke-Command @hSplitParamsRemote -ScriptBlock {
        param($CSRContent, $CAName, $TemplateName)
        $sConfig = "$env:COMPUTERNAME\$CAName"
        $sAttributes = if ($TemplateName) { "CertificateTemplate:$TemplateName" } else { "" }

        $certRequest = New-Object -ComObject CertificateAuthority.Request
        # 0x100 = CR_IN_BASE64HEADER (0x0) | CR_IN_PKCS10 (0x100)
        $iDisposition = $certRequest.Submit(0x100, $CSRContent, $sAttributes, $sConfig)
        $iRequestID = $certRequest.GetRequestId()

        return [PSCustomObject][ordered]@{
            Success     = $iDisposition -in @(3, 5)
            RequestID   = $iRequestID
            Disposition = $iDisposition
        }
    } -ArgumentList $hSplitParams.Native.CSRContent, $hSplitParams.Native.CAName, $hSplitParams.Native.TemplateName
}
