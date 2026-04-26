function Get-CertificateSAN {
    <#
    .SYNOPSIS
        Extracts Subject Alternative Name entries from an X.509 certificate, grouped by type

    .DESCRIPTION
        Reads the Subject Alternative Name extension (OID 2.5.29.17) from an X.509 certificate
        and returns a hashtable whose keys are SAN type names (DNS_NAME, IP_ADDRESS, RFC822_NAME,
        URL, ...) and whose values are arrays of the corresponding string values.

        Decoding relies on the X509enrollment.CX509ExtensionAlternativeNames COM object so the
        result is independent of the OS display language. The same type names as Get-CSRInfo
        are used for consistency.

    .PARAMETER Certificate
        The X509Certificate2 to read the SAN extension from.

    .OUTPUTS
        [hashtable]. Keys are SAN type names (DNS_NAME, IP_ADDRESS, ...). Values are string[].
        Types with no entries are omitted. Returns an empty hashtable when the certificate has no
        SAN extension.

    .EXAMPLE
        $san = Get-CertificateSAN -Certificate $cert
        $san.DNS_NAME
        $san.IP_ADDRESS

    .EXAMPLE
        (Get-CertificateSAN $cert).DNS_NAME | ForEach-Object { "dns: $_" }

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-04-22 - Loïc Ade
            - Initial release
            - Decodes the SAN extension via X509enrollment COM (locale independent)
            - Groups entries by SAN type using the same type names as Get-CSRInfo
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    Begin {
        function Convert-SANTypeToString {
            Param([Parameter(Mandatory, Position = 0)][int]$Type)
            switch ($Type) {
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
                default {"UNKNOWN"}
            }
        }

        function Convert-AlternativeNameValue {
            Param(
                [Parameter(Mandatory, Position = 0)][object]$ComAlternativeName,
                [Parameter(Mandatory, Position = 1)][string]$TypeName
            )
            switch ($TypeName) {
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
        }
    }
    Process {
        $hResult = @{}
        $oSANExt = $Certificate.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" } | Select-Object -First 1
        if (-not $oSANExt) { return $hResult }

        $oCom = New-Object -ComObject X509enrollment.CX509ExtensionAlternativeNames
        $sB64 = [Convert]::ToBase64String($oSANExt.RawData)
        $oCom.InitializeDecode(1, $sB64)  # XCN_CRYPT_STRING_BASE64 = 1

        foreach ($an in $oCom.AlternativeNames) {
            $sType = Convert-SANTypeToString $an.Type
            $sValue = Convert-AlternativeNameValue $an $sType
            if (-not $hResult.Contains($sType)) {
                $hResult[$sType] = @()
            }
            $hResult[$sType] += $sValue
        }
        return $hResult
    }
}
