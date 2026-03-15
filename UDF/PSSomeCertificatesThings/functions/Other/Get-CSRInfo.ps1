function Get-CSRInfo {
    <#
    .SYNOPSIS
        Retrieves information from a Certificate Signing Request file

    .DESCRIPTION
        Parses a CSR file and extracts detailed information including subject DN,
        Subject Alternative Names (SAN), certificate template name, hash algorithm,
        public key algorithm, and public key size. Uses X509Enrollment COM objects.

    .PARAMETER Path
        Path to the CSR file to parse.

    .OUTPUTS
        [PSCustomObject]. Object with Subject, SAN (array), TemplateName, HashAlgorithm, PublicKeyAlgorithm, PublicKeySize, and comObject properties.

    .EXAMPLE
        Get-CSRInfo -Path "C:\Certs\request.csr"

    .EXAMPLE
        $csrInfo = Get-CSRInfo -Path "C:\Temp\cert.req"
        $csrInfo.Subject
        $csrInfo.SAN | Format-Table Type, Value

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    Begin {
        function Convert-AlternativeName {
            Param(
                [Parameter(Mandatory, Position = 0)]
                [object]$ComAlternativeName
            )
            $sType = Convert-SANTypeToString $ComAlternativeName.Type 
            $sValue = switch ($sType) {
                "IP_ADDRESS" { 
                    $aIPItems = $ComAlternativeName.RawData(0x4).Split(" ")
                    if ($aIPItems.Count -eq 4) {
                        ($aIPItems | ForEach-Object { "0x" + $_ } | ForEach-Object { [int]$_ }) -join "."
                    } else {
                        $aIPItems -join ":"
                    }
                }
                Default { $ComAlternativeName.strValue }
            }
            return [PSCustomObject]@{
                Type = $sType
                Value = $sValue
            }
        }
        
        function Convert-SANTypeToString {
            Param(
                [Parameter(Mandatory, Position = 0)]
                [int]$Type
            )
            $result = switch ($type) {
                0 {"UNKNOWN"}
                1 {"OTHER_NAME"}
                2 {"RFC822_NAME"}
                3 {"DNS_NAME"}
                4 {"X400_ADDRESS"}
                5 {"DIRECTORY_NAME"}
                6 {"EDI_PARTY_NAME"}
                7 {"URL"}
                8 {"IP_ADDRESS"}
                9 {"REGISTERED_ID"}
                10 {"GUID"}
                11 {"USER_PRINCIPLE_NAME"}
            }
            return $result
        }

        function Convert-CertDN {
            Param(
                [Parameter(Mandatory, Position = 0)]
                [string]$DN
            )
            $allMatches = $DN | Select-String -Pattern "[A-Za-z]+=[^,]+" -AllMatches
            $aResult = for ($i = 1; $i -le $allMatches.Matches.Count; $i++) {
                $allMatches.Matches[0 - $i].Value
            }
            return ($aResult -join ",")
        }
    }
    Process {
        $CSRItem = Get-Content $Path
        $XComObjCSR = New-Object -ComObject X509enrollment.CX509CertificateRequestPkcs10 
        $XComObjCSR.InitializeDecode($CSRItem,6)
        $CertSANExtension = @($XComObjCSR.X509Extensions) | Where-Object{$_.objectid.value -eq "2.5.29.17"}
        $aSAN = if ($CertSANExtension) {
            $XComObjSAN = New-Object -ComObject X509enrollment.CX509ExtensionAlternativeNames
            $XComObjSAN.InitializeDecode(6, $CertSANExtension.RawData(3)) | Out-Null
            $XComObjSAN.AlternativeNames | ForEach-Object { Convert-AlternativeName $_ }
        } else {
            @()
        }
        $CertTemplateExtension = @($XComObjCSR.X509Extensions) | Where-Object{$_.objectid.value -eq "1.3.6.1.4.1.311.20.2"}
        $sTemplateName = if ($CertTemplateExtension) {
            $CertTemplateExtension.TemplateName
        } else {
            ""
        }
        $hResult = [pscustomobject]@{
            Subject = (Convert-CertDN $XComObjCSR.Subject.Name)
            SAN = $aSAN
            TemplateName = $sTemplateName
            HashAlgorithm = $XComObjCSR.HashAlgorithm.FriendlyName
            PublicKeyAlgorithm = $XComObjCSR.PublicKey.Algorithm.FriendlyName
            PublicKeySize = $XComObjCSR.PublicKey.Length
            comObject = $XComObjCSR
        }
        return $hResult
    }
}
