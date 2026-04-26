function Write-CSRInfoToHost {
    <#
    .SYNOPSIS
        Displays Certificate Signing Request information to the console

    .DESCRIPTION
        Outputs CSR information in a formatted manner to the console, including subject,
        Subject Alternative Names, and template name. Accepts either a CSR info object
        (from Get-CSRInfo) or a path to a CSR file.

    .PARAMETER CSRInfo
        CSR information object (from Get-CSRInfo).

    .PARAMETER Path
        Path to a CSR file.

    .OUTPUTS
        None. Displays information to console using Write-Host.

    .EXAMPLE
        Write-CSRInfoToHost -Path "C:\Certs\request.csr"

    .EXAMPLE
        $csrInfo = Get-CSRInfo -Path "C:\Temp\cert.req"
        Write-CSRInfoToHost -CSRInfo $csrInfo

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = "object")]
        [object]$CSRInfo,
        [Parameter(Mandatory, Position = 0, ParameterSetName = "path")]
        [string]$Path
    )
    Begin {
        $oCSRInfo = if ($PSCmdlet.ParameterSetName -eq "object") {
            $CSRInfo
        } else {
            Get-CSRInfo -Path $Path
        }
    }
    Process {
        Write-Host "Subject`t`t: $($oCSRInfo.Subject)"
        foreach ($sanITEM in $oCSRInfo.SAN) {
            Write-Host ("SAN " + ($sanITEM.Type -replace "_", " ") + "`t: " + $sanITEM.Value)
        }
        Write-Host ("Template Name`t: " + $oCSRInfo.TemplateName)
    }
}