function ConvertTo-Certificate {
    <#
    .SYNOPSIS
        Converts certificate data to an X509Certificate2 object

    .DESCRIPTION
        Converts various certificate representations to a System.Security.Cryptography.X509Certificates.X509Certificate2 object.
        Supports byte arrays and System.DirectoryServices.PropertyValueCollection objects.

    .PARAMETER Cert
        Certificate data to convert. Can be a byte array or PropertyValueCollection.

    .OUTPUTS
        [System.Security.Cryptography.X509Certificates.X509Certificate2]. The converted certificate object.

    .EXAMPLE
        $cert = ConvertTo-Certificate -Cert $certBytes

    .EXAMPLE
        $adCert = (Get-ADUser -Identity "user" -Properties userCertificate).userCertificate
        $cert = ConvertTo-Certificate -Cert $adCert

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$Cert
    )
    Begin {
        $oCert = if ($Cert -is [System.DirectoryServices.PropertyValueCollection]) {
            $Cert[0]
        } elseif ($Cert -is [byte[]]) {
            $Cert
        } else {
            throw [System.FormatException] "Can't convert `$Cert to a certificate"
        }
    }
    Process {
        $oResult = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 
        $oResult.Import([byte[]]$oCert)
    }
    End {
        return $oResult
    }
}