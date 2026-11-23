function Get-PKICARevocationUrls {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$CAName
    )

    $oRequest = $null
    try {
        $oRequest = New-Object -ComObject CertificateAuthority.Request -ErrorAction Stop
        $sConfiguration = "$ComputerName\$CAName"
        $sURLs = [string]$oRequest.GetCAProperty($sConfiguration, 41, 0, 4, 0)

        foreach ($sURL in ($sURLs -split '[\r\n]+')) {
            if (-not [string]::IsNullOrWhiteSpace($sURL)) {
                $sURL.Trim()
            }
        }
    }
    finally {
        if ($oRequest) {
            [void][Runtime.InteropServices.Marshal]::ReleaseComObject($oRequest)
        }
    }
}