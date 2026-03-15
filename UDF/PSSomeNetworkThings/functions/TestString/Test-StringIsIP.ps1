function Test-StringIsIP {
    <#
    .SYNOPSIS
        Tests if a string is a valid IP address, network, or range

    .DESCRIPTION
        Parses a string to determine if it's an IPv4/IPv6 address, a CIDR network,
        or an IP range. Returns a hashtable with parsed components (IP, mask, type,
        IP version) or $null if invalid.

    .PARAMETER string
        The string to test.

    .PARAMETER MandatoryMask
        Require a subnet mask in the input.

    .PARAMETER MaskForbidden
        Reject input if it contains a subnet mask.

    .PARAMETER RangeForbidden
        Reject input if it's an IP range.

    .PARAMETER Mask32AsHost
        Treat /32 networks as host addresses.

    .OUTPUTS
        [OrderedDictionary] or $null. Parsed IP information with Type, Category, IPVersion.

    .EXAMPLE
        Test-StringIsIP "192.168.1.0/24"

    .EXAMPLE
        Test-StringIsIP "10.0.0.1" -MaskForbidden

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

    [CmdletBinding(DefaultParameterSetName = "all")]
    Param(
        [Parameter(Mandatory, Position = 0, ParameterSetName = "all")]
        [Alias("InputString")]
        [string]$string,
        [switch]$MandatoryMask,
        [switch]$MaskForbidden,
        [switch]$RangeForbidden,
        [switch]$Mask32AsHost
    )
    Begin {
        if ($MandatoryMask.IsPresent -and $MaskForbidden.IsPresent) {
            throw [System.ArgumentException] "Mask can't be forbidden and mandatory at the same time"
        }
    }
    Process {
        $sIPv4Regex = "(?<ipv4>(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))"
        $sIPv6Regex = "(?<ipv6>((([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){5}:([0-9A-Fa-f]{1,4}:)?[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){4}:([0-9A-Fa-f]{1,4}:){0,2}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){3}:([0-9A-Fa-f]{1,4}:){0,3}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){2}:([0-9A-Fa-f]{1,4}:){0,4}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){6}((b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b).){3}(b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b))|(([0-9A-Fa-f]{1,4}:){0,5}:((b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b).){3}(b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b))|(::([0-9A-Fa-f]{1,4}:){0,5}((b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b).){3}(b((25[0-5])|(1d{2})|(2[0-4]d)|(d{1,2}))b))|([0-9A-Fa-f]{1,4}::([0-9A-Fa-f]{1,4}:){0,5}[0-9A-Fa-f]{1,4})|(::([0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,7}:)))"
        $sMaskv4Regex = "(?<maskv4>(((255\.){3}(255|254|252|248|240|224|192|128|0+))|((255\.){2}(255|254|252|248|240|224|192|128|0+)\.0)|((255\.)(255|254|252|248|240|224|192|128|0+)(\.0+){2})|((255|254|252|248|240|224|192|128|0+)(\.0+){3})))"
        $sMaskLengthV4Regex = "(?<masklengthv4>([1-2]?[0-9])|3[0-2])"
        $sMaskLengthV6Regex = "(?<masklengthv6>12[0-8]|1[0-1][0-9]|[1-9][0-9]|[0-9])"
        $sNetworkv4Regex = "(?<networkv4>$sIPv4Regex/($sMaskv4Regex|$sMaskLengthV4Regex))"
        $sNetworkv6Regex = "(?<networkv6>$sIPv6Regex/$sMaskLengthV6Regex)"
        $sRangev4Regex = "(?<ipv4range>(?<ipstart>$sIPv4Regex)-(?<ipend>$sIPv4Regex))"
        $sRangev6Regex = "(?<ipv6range>(?<ipstart>$sIPv6Regex)-(?<ipend>$sIPv6Regex))"
        $sRegex = "^$sNetworkv4Regex$|^$sNetworkv6Regex$|^$sRangev4Regex$|^$sRangev6Regex$|^(?<ipv4only>$sIPv4Regex)$|^(?<ipv6only>$sIPv6Regex)$"
        $ss = Select-String -InputObject $string -Pattern $sRegex -AllMatches
        if ($ss) {
            $hResult = Convert-MatchInfoToHashtable -InputObject $ss -ExcludeNumbers -ExcludeNull
            
            if ($hResult.masklengthv4) {
                $iMask = $hResult.masklengthv4 -as [int]
                $sBinaryMask = ("1"*$iMask+"0"*(32 - $iMask))
                $aBytesMask = @(
                    [convert]::ToByte($sBinaryMask.SubString(0,8),2),
                    [convert]::ToByte($sBinaryMask.SubString(8,8),2),
                    [convert]::ToByte($sBinaryMask.SubString(16,8),2),
                    [convert]::ToByte($sBinaryMask.SubString(24,8),2)
                )
                $hResult.maskv4 = New-Object -TypeName Net.IPAddress -ArgumentList @(,$aBytesMask)
            } elseif ($hResult.maskv4) {
                $hResult.masklengthv4 = switch ($hResult.maskv4) {
                    "0.0.0.0" { 0 }
                    "128.0.0.0" { 1 }
                    "192.0.0.0" { 2 }
                    "224.0.0.0" { 3 }
                    "240.0.0.0" { 4 }
                    "248.0.0.0" { 5 }
                    "252.0.0.0" { 6 }
                    "254.0.0.0" { 7 }
                    "255.0.0.0" { 8 }
                    "255.128.0.0" { 9 }
                    "255.192.0.0" { 10 }
                    "255.224.0.0" { 11 }
                    "255.240.0.0" { 12 }
                    "255.248.0.0" { 13 }
                    "255.252.0.0" { 14 }
                    "255.254.0.0" { 15 }
                    "255.255.0.0" { 16 }
                    "255.255.128.0" { 17 }
                    "255.255.192.0" { 18 }
                    "255.255.224.0" { 19 }
                    "255.255.240.0" { 20 }
                    "255.255.248.0" { 21 }
                    "255.255.252.0" { 22 }
                    "255.255.254.0" { 23 }
                    "255.255.255.0" { 24 }
                    "255.255.255.128" { 25 }
                    "255.255.255.192" { 26 }
                    "255.255.255.224" { 27 }
                    "255.255.255.240" { 28 }
                    "255.255.255.248" { 29 }
                    "255.255.255.252" { 30 }
                    "255.255.255.254" { 31 }
                    "255.255.255.255" { 32 }
                }
                $hResult.maskv4 = [ipaddress]$hResult.maskv4
            }
            if ($hResult.ipv4) {
                $hResult.ipv4 = [ipaddress]$hResult.ipv4
            }

            if ($hResult.networkv4 -and $hResult.ipv4 -and $hResult.maskv4) {
                $ipBytes = $hResult.ipv4.GetAddressBytes()
                $maskBytes = $hResult.maskv4.GetAddressBytes()
                $networkBytes = @(
                    ($ipBytes[0] -band $maskBytes[0]),
                    ($ipBytes[1] -band $maskBytes[1]),
                    ($ipBytes[2] -band $maskBytes[2]),
                    ($ipBytes[3] -band $maskBytes[3])
                )
                $hResult.ipv4 = New-Object -TypeName Net.IPAddress -ArgumentList @(,$networkBytes)
            }

            if (($hResult.masklengthv4 -or $hResult.masklengthv6) -and ($MaskForbidden)) {
                return $null
            }
            if (($MandatoryMask) -and ($null -eq $hResult.masklengthv4) -and ($null -eq $hResult.maskv6) -and ($null -eq $hResult.maskv4)) {
                return $null
            }
            if (($hResult.ipv4range) -or ($hResult.ipv6range)) {
                if ($RangeForbidden) {
                    return $null
                }
                $hResult.ipend = [ipaddress]($hResult.ipend)
                $hResult.ipstart = [ipaddress]($hResult.ipstart)
                if ($hResult.ipend.Address -lt $hResult.ipstart.Address) {
                    return $false
                }
                $hResult.Remove("ipv4")
                $hResult.Remove("ipv6")
            }
            $oResultType = if (($hResult.ipv4range) -or ($hResult.ipv6range)) {
                "Range"
            } elseif (($hResult.networkv4) -or ($hResult.sNetworkv6Regex)) {
                "Network"
            } else {
                "Address"
            }
            $oResultIPVersion = if (($hResult.ipv4range) -or ($hResult.networkv4) -or ($hResult.ipv4only)) {
                4
            } else {
                6
            }
            $hResult.Type = $oResultType
            $hResult.Category = "IP"
            $hResult.IPVersion = $oResultIPVersion
            if ($Mask32AsHost -and ($hResult.Type -eq "Network") -and ($hResult.masklengthv4 -eq 32)) {
                $hResult = [ordered]@{
                    "ipv4" = $hResult.ipv4
                    "ipv4only" = $hResult.ipv4
                    Type = "Address"
                    Category = "IP"
                    IPVersion = 4
                }
            }
            $hResult.String = switch ($hResult.Type) {
                    "Address" { $hResult.ipv4.ToString() }
                    "Network" { $hResult.ipv4.ToString() + "/" + $hResult.masklengthv4 }
                    "Range"   { $hResult.ipv4range }
            }
            return $hResult
        } else {
            return $null
        }
    }
}