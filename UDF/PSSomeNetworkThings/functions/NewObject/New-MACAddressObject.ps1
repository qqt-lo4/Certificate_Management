function New-MACAddressObject {
    <#
    .SYNOPSIS
        Creates a MAC address object

    .DESCRIPTION
        Parses a MAC address string into a custom object with Format() and
        ToString() methods for flexible output formatting (e.g. "XX:XX:XX:XX:XX:XX",
        "xx-xx-xx-xx-xx-xx", "XXXX.XXXX.XXXX").

    .PARAMETER Value
        The MAC address string in any common format.

    .OUTPUTS
        [PSCustomObject]. MAC address object with OriginalValue, Value, Format(), and ToString().

    .EXAMPLE
        $mac = New-MACAddressObject "AA:BB:CC:DD:EE:FF"
        $mac.Format("XX-XX-XX-XX-XX-XX")

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Value
    )
    $ss = Select-String -InputObject $Value -Pattern (Get-MacAddressRegex -FullLine)
    $cleanMAC = ($ss.Matches.Groups | Where-Object { $_.Name -eq "symbols" }).Captures.Value -join ""
    
    $macObject = [PSCustomObject]@{
        OriginalValue = $Value
        Value = $cleanMAC
    }
    
    $macObject | Add-Member -MemberType ScriptMethod -Name "Format" -Value {
        Param(
            [string]$Format
        )
        $iMacAddressIndex = 0
        $sResult = ""
        for ($i = 0; $i -lt $Format.Length; $i++) {
            if ($Format[$i].ToString().ToLower() -eq "x") {
                if ($Format[$i] -ceq "x") {
                    $sResult += $this.Value[$iMacAddressIndex].ToString().ToLower()
                } else {
                    $sResult += $this.Value[$iMacAddressIndex].ToString().ToUpper()
                }
                $iMacAddressIndex += 1
            } else {
                $sResult += $Format[$i]
            }
        }
        return $sResult
    }
    
    $macObject | Add-Member -MemberType ScriptMethod -Name "ToString" -Force -Value {
        return $this.Format("XX:XX:XX:XX:XX:XX")
    }

    $macObject.PSTypeNames.Insert(0, "Mac Address")

    return $macObject
}