function Convert-ADDateTime {
    <#
    .SYNOPSIS
        Converts an Active Directory large integer date/time value to a readable format

    .DESCRIPTION
        Converts AD large integer timestamps (such as lastLogonTimestamp, accountExpires,
        pwdLastSet) to UTC DateTime objects. Returns "Never" if the value is 0 or the
        maximum value for its type.

    .PARAMETER InputDate
        The AD large integer date/time value to convert.

    .OUTPUTS
        [datetime] or [string]. A UTC DateTime object, or "Never" if the value represents no expiration.

    .EXAMPLE
        Convert-ADDateTime -InputDate $user.pwdLastSet

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [object]$InputDate
    )
    if ($InputDate -in @(0, ($InputDate.GetType())::MaxValue)) {
        return "Never"
    } else {
        return [datetime]::FromFileTimeUtc($InputDate)
    }
}
