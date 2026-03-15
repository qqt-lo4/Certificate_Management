function New-IPv4Object {
    <#
    .SYNOPSIS
        Creates an IPv4 address object

    .DESCRIPTION
        Converts a string IP address or uint32 value into a custom IPv4 object
        with a numeric Value property and a ToString() method for display.

    .PARAMETER InputObject
        An IPv4 address string (e.g. "192.168.1.1") or a uint32 value.

    .OUTPUTS
        [PSCustomObject]. IPv4 object with Value (uint32), Type ("IP"), and ToString() method.

    .EXAMPLE
        $ip = New-IPv4Object "192.168.1.1"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

    Param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [object]$InputObject
    )
    [uint32]$iIPResult = if ($InputObject -is [uint32]) {
        $InputObject
    } elseif ($InputObject -is [string]) {
        if ($InputObject -match (Get-IPRegex -IPv4 -FullLine)) {
            $aIP = $InputObject.Split(".")
            $iResult = 0
            for ($i = 0; $i -lt 4; $i++) {
                $iResult += [uint32]$aIP[$i] * [Math]::Pow(256, $aIP.Count - $i - 1)
            }
            $iResult
        } else {
            throw [System.ArgumentException] "Input Object is not a valid string IP"
        }
    } else {
        throw [System.ArgumentException] "Input Object is not a valid object"
    }
    $hResult = [pscustomobject]@{
        Value = $iIPResult
        Type = "IP"
    }
    $hResult | Add-Member -MemberType ScriptMethod -Name "ToString" -Force -Value {
        $iLastByte = [int]($this.Value % 256)
        $iThirdByte = [int]($this.Value -shr 8) % 256
        $iSecondByte = [int]($this.Value -shr 16) % 256
        $iFirstByte = [int]($this.Value -shr 24)
        return "" + $iFirstByte + "." + $iSecondByte + "." + $iThirdByte + "." + $iLastByte
    }
    $hResult.PSTypeNames.Insert(0, "IP Address")
    return $hResult
}