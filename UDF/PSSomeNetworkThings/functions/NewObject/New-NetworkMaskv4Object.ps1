function New-NetworkMaskv4Object {
    <#
    .SYNOPSIS
        Creates an IPv4 network mask object

    .DESCRIPTION
        Converts a subnet mask string (e.g. "255.255.255.0"), a prefix length
        (e.g. 24), or an integer into a mask object with a GetMaskLength() method.

    .PARAMETER InputMask
        Subnet mask as a dotted string, prefix length string, or integer.

    .OUTPUTS
        [PSCustomObject]. Mask object with Value (uint32), Type ("Mask"), ToString(), and GetMaskLength().

    .EXAMPLE
        $mask = New-NetworkMaskv4Object "255.255.255.0"

    .EXAMPLE
        $mask = New-NetworkMaskv4Object 24

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

    Param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [object]$InputMask
    )
    $sMaskv4Regex = "^(?<maskv4>(((255\.){3}(255|254|252|248|240|224|192|128|0+))|((255\.){2}(255|254|252|248|240|224|192|128|0+)\.0)|((255\.)(255|254|252|248|240|224|192|128|0+)(\.0+){2})|((255|254|252|248|240|224|192|128|0+)(\.0+){3})))$"
    $sMaskLengthV4Regex = "^(?<masklengthv4>([1-2]?[0-9])|3[0-2])$"
    $oResult = if ($InputMask -is [string]) {
        if ($InputMask -match $sMaskv4Regex) {
            New-IPv4Object -InputObject $InputMask
        } elseif ($InputMask -match $sMaskLengthV4Regex) {
            [uint32]$uIntIP = 0
            $iMask = $InputMask -as [int]
            for ($i = 31; $i -ge (32 - $iMask); $i--) {
                $uIntIP += [Math]::Pow(2, $i)
            }
            New-IPv4Object -InputObject $uIntIP
        } else {
            throw [System.ArgumentException] "Input is noty a valid IPv4 mask"
        }
    } elseif ($InputMask -is [int]) {
        [uint32]$uIntIP = 0
        $iMask = $InputMask -as [int]
        if (($iMask -gt 32) -or ($iMask -lt 0)) {
            throw [System.ArgumentOutOfRangeException] "Mask is not valid"
        }
        for ($i = 31; $i -ge (32 - $iMask); $i--) {
            $uIntIP += [Math]::Pow(2, $i)
        }
        New-IPv4Object -InputObject $uIntIP    
    }
    $oResult.Type = "Mask"
    $oResult | Add-Member -MemberType ScriptMethod -Name "GetMaskLength" -Value {
        $iResult = switch ($this.ToString()) {
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
        return $iResult
    }
    $oResult.PSTypeNames.Insert(0, "Network Mask")
    return $oResult
}