function Set-LAPSPasswordExpiration {
    <#
    .SYNOPSIS
        Sets the LAPS password expiration date for an AD computer

    .DESCRIPTION
        Modifies the LAPS password expiration attribute to force a password rotation.
        Supports both legacy LAPS (ms-Mcs-AdmPwdExpirationTime) and Windows LAPS
        (msLAPS-PasswordExpirationTime). Provides preset durations or a custom date.

    .PARAMETER ADComputer
        The AD computer object to modify.

    .PARAMETER Credential
        Optional PSCredential for AD authentication.

    .PARAMETER ExpirationDate
        A custom expiration date. Alias: Date.

    .PARAMETER TenMinutes
        Set expiration to 10 minutes from now.

    .PARAMETER OneHour
        Set expiration to 1 hour from now.

    .PARAMETER FourHours
        Set expiration to 4 hours from now.

    .PARAMETER OneDay
        Set expiration to 1 day from now.

    .OUTPUTS
        System.DateTime. The new expiration date.

    .EXAMPLE
        Set-LAPSPasswordExpiration -ADComputer $computer -OneHour

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADComputer,
        [pscredential]$Credential,
        [Parameter(Position = 1, ParameterSetName = "Custom")]
        [Alias("Date")]
        [datetime]$ExpirationDate,
        [Parameter(ParameterSetName = "10m")]
        [switch]$TenMinutes,
        [Parameter(ParameterSetName = "1h")]
        [switch]$OneHour,
        [Parameter(ParameterSetName = "4h")]
        [switch]$FourHours,
        [Parameter(ParameterSetName = "1d")]
        [switch]$OneDay
    )
    if ($ADComputer.PSTypeNames[0] -eq "ADComputer") {
        $dExpirationDate = if ($PSCmdlet.ParameterSetName -eq "Custom") {
            $ExpirationDate
        } else {
            switch ($PSCmdlet.ParameterSetName) {
                "10m" {
                    (Get-Date).AddMinutes(10)
                }
                "1h" {
                    (Get-Date).AddHours(1)
                }
                "4h" {
                    (Get-Date).AddHours(4)
                }
                "1d" {
                    (Get-Date).AddDays(1)
                }
            }
        }
        $sAttribute = if ($ADComputer."msLAPS-PasswordExpirationTime") {
            "msLAPS-PasswordExpirationTime"
        } else {
            "ms-Mcs-AdmPwdExpirationTime"
        }
        $hAttribute = @{
            $sAttribute = $dExpirationDate.ToFileTimeUtc().ToString()
        }
        if ($Credential) {
            Set-ADObjectAttribute -Object $ADComputer -Attribute $hAttribute -Credential $Credential
        } else {
            Set-ADObjectAttribute -Object $ADComputer -Attribute $hAttribute
        }
        return $dExpirationDate
    } else {
        throw "`$ADComputer is not a computer"
    }
}