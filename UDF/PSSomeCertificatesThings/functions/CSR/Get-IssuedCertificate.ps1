# function Get-IssuedCertificate {
#     <#
#     .SYNOPSIS
#         Retrieves an issued certificate from a Certificate Authority

#     .DESCRIPTION
#         Fetches an issued certificate and its certificate chain from a Windows Certificate Authority
#         using certreq -retrieve. Supports remote execution via PSSession and automatically copies
#         certificate files from remote server to local paths.

#     .PARAMETER Session
#         PSSession to execute the command remotely.

#     .PARAMETER RequestID
#         The Request ID of the issued certificate on the CA.

#     .PARAMETER CAName
#         Name of the Certificate Authority.

#     .PARAMETER CertOut
#         Output path for the certificate file.

#     .PARAMETER CertChainOut
#         Output path for the certificate chain file.

#     .PARAMETER PKIWorkFolder
#         Working folder on the remote server for temporary certificate files.

#     .OUTPUTS
#         [PSCustomObject]. Object with Success (boolean), ExitCode (int), Output (string array), and optionally Cert and CertChain (file paths) properties.

#     .EXAMPLE
#         Get-IssuedCertificate -RequestID "123" -CAName "CompanyCA" -CertOut "C:\Certs\cert.cer" -CertChainOut "C:\Certs\chain.p7b" -PKIWorkFolder "C:\Temp"

#     .EXAMPLE
#         $session = New-PSSession -ComputerName "CA-Server"
#         Get-IssuedCertificate -Session $session -RequestID "456" -CAName "RootCA" -CertOut "cert.cer" -CertChainOut "chain.p7b" -PKIWorkFolder "C:\Temp"

#     .NOTES
#         Author  : Loïc Ade
#         Version : 1.0.0
#     #>
#     [CmdletBinding()]
#     Param(
#         [System.Management.Automation.Runspaces.PSSession]$Session,
#         [string]$RequestID,
#         [string]$CAName,
#         [string]$CertOut,
#         [string]$CertChainOut,
#         [string]$PKIWorkFolder
#     )

#     function Add-Quote {
#         Param(
#             [string]$Text
#         )
#         $result = if ($Text.Contains(" ")) { "`"$Text`"" } else { $Text }
#         return $result
#     }

#     function Remove-RemoteFile {
#         Param(
#             [Parameter(Mandatory)]
#             [string]$Path,
#             [Parameter(Mandatory)]
#             [System.Management.Automation.Runspaces.PSSession]$Session
#         )
#         Invoke-Command -ScriptBlock { Remove-Item $args[0] } -Session $Session -ArgumentList $Path
#     }

#     if ($Session) {
#         $oResult = Invoke-ThisFunctionRemotely -ThisFunctionName $MyInvocation.InvocationName -ThisFunctionParameters $PSBoundParameters
#         if ($oResult.Success) {
#             Copy-Item -Path ($PKIWorkFolder + "\" + (Split-path $CertOut -Leaf)) -Destination $CertOut -FromSession $Session
#             Copy-Item -Path ($PKIWorkFolder + "\" + (Split-path $CertChainOut -Leaf)) -Destination $CertChainOut -FromSession $Session
#             Remove-RemoteFile -Session $Session -Path ($PKIWorkFolder + "\" + (Split-path $CertChainOut -Leaf))
#             Remove-RemoteFile -Session $Session -Path ($PKIWorkFolder + "\" + (Split-path $CertOut -Leaf))
#             $oResult | Add-Member -NotePropertyName "Cert" -NotePropertyValue $CertOut
#             $oResult | Add-Member -NotePropertyName "CertChain" -NotePropertyValue $CertChainOut
#         }
#         return $oResult
#     } else {
#         $aCertReqArgs = @("-retrieve")
#         $aCertReqArgs += "-q"
#         $aCertReqArgs += "-v"
#         $aCertReqArgs += "-f"
#         $aCertReqArgs += "-config"
#         $aCertReqArgs += (Add-Quote ($(hostname) + "\" + $CAName))
#         $aCertReqArgs += $RequestID
#         $aCertReqArgs +=  (Add-Quote ($PKIWorkFolder + "\" + (Split-path $CertOut -Leaf)))
#         $aCertReqArgs +=  (Add-Quote ($PKIWorkFolder + "\" + (Split-path $CertChainOut -Leaf)))
#         Write-Verbose ("certreq " + ($aCertReqArgs -join " "))
#         $output = $(certreq $aCertReqArgs)
#         $certreqSuccess = ($LastExitCode -eq 0)
#         $iExitCode = $LastExitCode
#         $hResult = [ordered]@{
#             Success = $certreqSuccess
#             ExitCode = $iExitCode
#             Output = $output
#         }
#         return New-Object -TypeName psobject -Property $hResult
#     }
# }

function Get-IssuedCertificate {
    <#
    .SYNOPSIS
        Retrieves an issued certificate from a Certificate Authority

    .DESCRIPTION
        Fetches an issued certificate and its certificate chain from a Windows Certificate Authority
        using the ICertRequest2 COM interface. The certificate content is retrieved directly via the API,
        eliminating the need for temporary files on the remote server.
        Supports local and remote execution via PSSession or ComputerName.

    .PARAMETER Session
        PSSession to execute the command remotely on the CA server.

    .PARAMETER ComputerName
        Name of the remote computer to execute the command on.

    .PARAMETER Credential
        Credentials for remote execution (used with ComputerName).

    .PARAMETER RequestID
        The Request ID of the issued certificate on the CA.

    .PARAMETER CAName
        Name of the Certificate Authority.

    .PARAMETER CertOut
        Local output path for the certificate file (.cer).

    .PARAMETER CertChainOut
        Local output path for the certificate chain file (.p7b).

    .OUTPUTS
        [PSCustomObject] with properties:
            - Success   : [bool] True if disposition is Issued (3)
            - Cert      : [string] Path to the certificate file (if successful)
            - CertChain : [string] Path to the certificate chain file (if successful)

    .EXAMPLE
        Get-IssuedCertificate -RequestID "123" -CAName "CompanyCA" -CertOut "C:\Certs\cert.cer" -CertChainOut "C:\Certs\chain.p7b"

    .EXAMPLE
        $session = New-PSSession -ComputerName "CA-Server" -Credential $cred
        Get-IssuedCertificate -Session $session -RequestID "456" -CAName "RootCA" -CertOut "cert.cer" -CertChainOut "chain.p7b"

    .NOTES
        Author  : Loïc Ade
        Version : 2.0.0

        1.0.0 - Initial version using certreq command line with file copy
        2.0.0 (2026-03-15)
            - Uses ICertRequest2 COM interface instead of certreq
            - Removed PKIWorkFolder parameter (no temporary files needed)
            - Certificate content retrieved via API and written locally
            - Uses Split-RemoteAndNativeParameters with Invoke-Command splatting
    #>
    [CmdletBinding()]
    Param(
        [System.Management.Automation.Runspaces.PSSession]$Session,
        [string]$ComputerName,
        [PSCredential]$Credential,
        [Parameter(Mandatory)]
        [string]$RequestID,
        [Parameter(Mandatory)]
        [string]$CAName,
        [Parameter(Mandatory)]
        [string]$CertOut,
        [Parameter(Mandatory)]
        [string]$CertChainOut
    )

    $hSplitParams = Split-RemoteAndNativeParameters
    $hRemote = $hSplitParams.Remote

    $oRemoteResult = Invoke-Command @hRemote -ScriptBlock {
        param($RequestID, $CAName)
        $sConfig = "$env:COMPUTERNAME\$CAName"

        $certRequest = New-Object -ComObject CertificateAuthority.Request
        # CR_OUT_BASE64HEADER = 0x0, CR_OUT_BASE64 = 0x1, CR_OUT_CHAIN = 0x100
        $iDisposition = $certRequest.RetrievePending($RequestID, $sConfig)

        if ($iDisposition -eq 3) { # Issued
            $sCertBase64 = $certRequest.GetCertificate(0x0)    # CR_OUT_BASE64HEADER
            $sChainBase64 = $certRequest.GetCertificate(0x100) # CR_OUT_CHAIN = full certificate chain

            return [PSCustomObject][ordered]@{
                Success   = $true
                Cert      = $sCertBase64
                CertChain = $sChainBase64
            }
        } else {
            return [PSCustomObject][ordered]@{
                Success   = $false
                Cert      = $null
                CertChain = $null
            }
        }
    } -ArgumentList $hSplitParams.Native.RequestID, $hSplitParams.Native.CAName

    if ($oRemoteResult.Success) {
        # CER: API returns content with PEM headers already included
        [System.IO.File]::WriteAllText($CertOut, $oRemoteResult.Cert)
        # P7B: API returns chain with PEM headers (BEGIN CERTIFICATE)
        [System.IO.File]::WriteAllText($CertChainOut, $oRemoteResult.CertChain)
        return [PSCustomObject][ordered]@{
            Success   = $true
            Cert      = $CertOut
            CertChain = $CertChainOut
        }
    } else {
        return [PSCustomObject][ordered]@{
            Success   = $false
            Cert      = $null
            CertChain = $null
        }
    }
}
