function Convert-ADTimeSpan {
    <#
    .SYNOPSIS
        Converts an AD large-integer duration value to a TimeSpan.

    .DESCRIPTION
        Active Directory stores duration attributes (maxPwdAge, minPwdAge,
        lockoutDuration, lockoutObservationWindow, etc.) as negative 64-bit
        values in 100-nanosecond intervals.

        This function handles the IADsLargeInteger COM object format returned
        by System.DirectoryServices as well as plain Int64 values. A zero or
        Int64.MinValue input returns [TimeSpan]::Zero.

    .PARAMETER Value
        The raw value from a DirectorySearcher result property. Can be an
        IADsLargeInteger COM object or an Int64.

    .OUTPUTS
        System.TimeSpan. The absolute duration represented by the value.

    .EXAMPLE
        Convert-ADTimeSpan -Value $result.Properties['maxpwdage'][0]

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        1.0.0 (2026-04-12) - Initial version
    #>
    Param(
        [Parameter(Mandatory)]
        [object]$Value
    )

    # Convert IADsLargeInteger COM object to Int64 if needed
    if ($Value -is [System.__ComObject]) {
        $iHigh = $Value.GetType().InvokeMember("HighPart", [System.Reflection.BindingFlags]::GetProperty, $null, $Value, $null)
        $iLow  = $Value.GetType().InvokeMember("LowPart",  [System.Reflection.BindingFlags]::GetProperty, $null, $Value, $null)
        $iValue = [int64]$iHigh * 4294967296 + [int64]([uint32]$iLow)
    } else {
        $iValue = [int64]$Value
    }

    if ($iValue -eq 0 -or $iValue -eq [int64]::MinValue) {
        return [TimeSpan]::Zero
    }

    # AD stores durations as negative ticks — take the absolute value
    return [TimeSpan]::FromTicks([Math]::Abs($iValue))
}
