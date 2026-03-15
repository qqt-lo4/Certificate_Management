function New-Networkv4Object {
    <#
    .SYNOPSIS
        Creates an IPv4 network object

    .DESCRIPTION
        Parses a CIDR notation or IP/mask string into a network object with
        calculated properties: network address, mask, first/last usable IPs,
        broadcast, host counts. Includes ToString() and ChangeMask() methods.

    .PARAMETER InputString
        Network in CIDR notation (e.g. "192.168.1.0/24") or IP address.

    .PARAMETER Mask
        Optional subnet mask or prefix length (used with InputString).

    .OUTPUTS
        [OrderedDictionary]. Network object with Network, Mask, First, Last, UsableHosts, TotalHosts, Broadcast.

    .EXAMPLE
        $net = New-Networkv4Object "192.168.1.0/24"

    .EXAMPLE
        $subnets = (New-Networkv4Object "10.0.0.0/16").ChangeMask(24)

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$InputString,
        [string]$Mask
    )
    Begin {
        $sInput = if ($Mask) {
            $InputString + "/" + $Mask
        } else {
            $InputString
        }
        $hTestResult = Test-StringIsIP -string $sInput -MandatoryMask
        if (-not $hTestResult) {
            throw [System.ArgumentException] "Invalid input : it's not a network"
        }
    }
    Process {
        $oIP = New-IPv4Object -InputObject $hTestResult.ipv4.ToString()
        $oMask = if ($hTestResult.maskv4) {
            New-NetworkMaskv4Object -InputMask $hTestResult.maskv4.ToString()
        } else{
            New-NetworkMaskv4Object -InputMask $hTestResult.masklengthv4.ToString()
        }
        $oNetworkIP = New-IPv4Object -InputObject ($oIP.Value -band $oMask.Value)
        
        $oBroadcast = New-IPv4Object ($oNetworkIP.Value -bor -bnot $oMask.Value)
        $iMaskLength = $oMask.GetMaskLength()
        $oFirstIP = if ($iMaskLength -le 30) { New-IPv4Object ($oNetworkIP.Value + 1) } else { $null }
        $oLastIP = if ($iMaskLength -le 30) { New-IPv4Object ($oBroadcast.Value - 1) } else { $null }
        [uint32]$iTotalHosts = [Math]::Pow(2, 32 - $iMaskLength)
        [uint32]$iUsableHosts = switch ($iMaskLength) {
            32 { 1 }
            31 { 2 }
            default { $iTotalHosts - 2}
        }
        
        $hResult = [ordered]@{
            Network = $oNetworkIP
            Mask = $oMask
            First = $oFirstIP
            Last = $oLastIP
            UsableHosts = $iUsableHosts
            TotalHosts = $iTotalHosts
            Broadcast = $oBroadcast
            Type = "Network"
        }
        $hResult | Add-Member -MemberType ScriptMethod -Name "ToString" -Force -Value {
            Param(
                [bool]$FullMask = $false
            )
            if ($FullMask) {
                return $this.Network.ToString() + "/" + $this.Mask.ToString()
            } else {
                return $this.Network.ToString() + "/" + $this.Mask.GetMaskLength().ToString()
            }
        }
        $hResult | Add-Member -MemberType ScriptMethod -Name "ChangeMask" -Force -Value {
            Param(
                [int]$NewMask
            )
            if ($NewMask -eq $this.Mask.GetMaskLength()) {
                return $this
            } elseif ($NewMask -lt $this.Mask.GetMaskLength()) {
                return New-Networkv4Object -InputString $this.Network.ToString() -Mask $NewMask
            } else {
                $aResult = @()
                $iChangeSize = $NewMask - $this.Mask.GetMaskLength()
                $iNewRangesCount = [System.Math]::Pow(2, $iChangeSize)
                for ($i = 0; $i -lt $iNewRangesCount; $i++) {
                    [uint32]$uNewIPRange = $this.Network.Value + ($i * [System.Math]::Pow(2, 32 - $NewMask))
                    $oNewIP = New-IPv4Object -InputObject $uNewIPRange
                    $aResult += New-Networkv4Object ($oNewIP.ToString() + "/" + $NewMask)
                }
                return $aResult
            }
        }
        $hResult.PSTypeNames.Insert(0, "Network")
        return $hResult
    }
}