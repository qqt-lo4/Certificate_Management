function New-IPv4RangeObject {
    <#
    .SYNOPSIS
        Creates an IPv4 range object

    .DESCRIPTION
        Creates a custom object representing an IPv4 address range with First,
        Last, Count properties and a ToString() method. Accepts two IPs or a
        single range string (e.g. "10.0.0.1-10.0.0.254").

    .PARAMETER FirstIP
        The first IP address of the range (string or IPv4 object).

    .PARAMETER LastIP
        The last IP address of the range (string or IPv4 object).

    .OUTPUTS
        [Hashtable]. Range object with First, Last, Count, Type, and ToString().

    .EXAMPLE
        $range = New-IPv4RangeObject "10.0.0.1" "10.0.0.254"

    .EXAMPLE
        $range = New-IPv4RangeObject "10.0.0.1-10.0.0.254"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

    Param(
        [Parameter(Mandatory, Position = 0)]
        [Alias("First")]
        [object]$FirstIP,
        [Parameter(Position = 1)]
        [Alias("Last")]
        [object]$LastIP
    )
    $oFirstIP, $oLastIP = if ($FirstIP -and $LastIP) {
        New-IPv4Object $FirstIP
        New-IPv4Object $LastIP
    } else {
        if ($FirstIP -is [string]) {
            $hTestResult = Test-StringIsIP -string $FirstIP
            if ($hTestResult.Type -eq "range") {
                New-IPv4Object $hTestResult.ipstart.ToString()
                New-IPv4Object $hTestResult.ipend.ToString()
            }
        } else {
            throw [System.ArgumentException] "First object type is not supported"
        }
    }
    if ($oFirstIP.Value -gt $oLastIP.Value) {
        throw [System.ArgumentOutOfRangeException] "Last IP is before first IP"
    }
    $hResult = @{
        First = $oFirstIP
        Last = $oLastIP
        Count = $oLastIP.Value - $oFirstIP.Value + 1
        Type = "Range"
    }
    $hResult | Add-Member -MemberType ScriptMethod -Name "ToString" -Force -Value {
        return $this.First.ToString() + "-" + $this.Last.ToString()
    }
    $hResult.PSTypeNames.Insert(0, "IP Range")
    return $hResult
}