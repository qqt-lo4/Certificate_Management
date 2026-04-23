function ConvertFrom-X500DistinguishedName {
    <#
    .SYNOPSIS
        Parses an X.500 Distinguished Name string into a hashtable of attributes

    .DESCRIPTION
        Takes a Distinguished Name string (as found in certificate Subject or Issuer fields)
        and returns an ordered hashtable keyed by attribute short name (CN, O, OU, L, ST, C, E, DC, ...).
        Parsing delegates to System.Security.Cryptography.X509Certificates.X500DistinguishedName
        so escaped characters and quoted values are handled correctly.

        When an attribute appears more than once in the DN, only the first occurrence is kept in
        the hashtable; callers that need every value should use X500DistinguishedName directly.

    .PARAMETER DistinguishedName
        The DN string to parse, for instance "CN=www.example.com, OU=IT, O=ACME, L=Paris, C=FR".

    .OUTPUTS
        [System.Collections.Specialized.OrderedDictionary]. Attribute short names (uppercase) mapped to values.

    .EXAMPLE
        ConvertFrom-X500DistinguishedName -DistinguishedName "CN=www.example.com, OU=IT, O=ACME, C=FR"

    .EXAMPLE
        $h = ConvertFrom-X500DistinguishedName $cert.Subject
        $h.CN
        $h.O

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-04-22 - Loïc Ade
            - Initial release
            - Delegates parsing to [X500DistinguishedName]::Format($true)
            - Returns the first occurrence when an attribute appears multiple times
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$DistinguishedName
    )
    $hResult = [ordered]@{}
    $oDN = New-Object System.Security.Cryptography.X509Certificates.X500DistinguishedName $DistinguishedName
    foreach ($sLine in ($oDN.Format($true) -split "`r`n|`n")) {
        if ($sLine -match '^\s*([A-Za-z]+)\s*=\s*(.*)$') {
            $sKey = $matches[1].ToUpper()
            $sValue = $matches[2].Trim()
            if (-not $hResult.Contains($sKey)) {
                $hResult[$sKey] = $sValue
            }
        }
    }
    return $hResult
}
