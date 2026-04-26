function Convert-P7BToCer {
    <#
    .SYNOPSIS
        Converts a P7B certificate file to CER format

    .DESCRIPTION
        Converts a PKCS#7 (.p7b) certificate bundle to CER format using OpenSSL.
        Extracts all certificates from the P7B file and saves them to a CER file.

    .PARAMETER P7bPath
        Path to the P7B file to convert.

    .PARAMETER OutCerFile
        Output path for the CER file. If not specified, uses the P7B filename with .cer extension.

    .PARAMETER OpenSSLPath
        Path to OpenSSL executable or directory containing openssl.exe. If not specified, searches in PATH.

    .OUTPUTS
        None. Creates a CER file at the specified output path.

    .EXAMPLE
        Convert-P7BToCer -P7bPath "C:\Certs\chain.p7b"

    .EXAMPLE
        Convert-P7BToCer -P7bPath "C:\Certs\chain.p7b" -OutCerFile "C:\Certs\certificates.cer" -OpenSSLPath "C:\OpenSSL\bin"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    [CmdletBinding()]
    Param(
        [ValidateScript({
            if($_ -and (-not (Test-Path -Path $_ -PathType Leaf))){
                throw "P7b file does not exist"
            }
            return $true
        })]
        [string]$P7bPath,
        [string]$OutCerFile,
        [string]$OpenSSLPath
    )
    
    function Add-Quote {
        Param(
            [string]$Text
        )
        $result = if ($Text.Contains(" ")) { "`"$Text`"" } else { $Text }
        return $result
    }

    function Get-OpenSSLPath {
        Param(
            [string]$Inputpath
        )
        if ($Inputpath) {
            if (Test-Path $InputPath -PathType Leaf) {
                return $Inputpath
            } elseif (Test-Path ($Inputpath + "\openssl.exe")) {
                return $Inputpath + "\openssl.exe"
            } else {
                return ""
            }
        } else {
            try {
                return (Get-Command openssl).Source
            } catch {
                return "" 
            }
        }
    }

    # Find OpenSSL
    $openSSL = Get-OpenSSLPath $OpenSSLPath

    # Build out file path
    $sOutPath = if ($OutCerFile) { $OutCerFile } else { $P7bPath + ".cer" }

    # Convert P7B to CER
    $aOpenSSLArgs = @("pkcs7", "-print_certs", "-in", (Add-Quote $P7bPath), "-out", $sOutPath)
	Write-Verbose -Message ("openssl " + ([System.String]::Join(" ", $aOpenSSLArgs)))
    &$openssl @aOpenSSLArgs
}