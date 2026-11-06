function Get-UserInfoRegex {
    <#
    .SYNOPSIS
        Returns a regex pattern for matching URI user information (user:pass@)

    .DESCRIPTION
        Generates a regex pattern that matches the userinfo component of a URI
        as defined in RFC 3986, including username and optional password followed by '@'.

    .OUTPUTS
        System.String. The regex pattern with a named capture group 'UserInfo'.

    .EXAMPLE
        $pattern = Get-UserInfoRegex
        "admin:secret@" -match $pattern

    .NOTES
        Author  : Loïc Ade
        Version : 1.1.0

        1.1.0 (2026-11-06)
            - ":" accepted (RFC 3986 userinfo): "user:pass@" was refused
    #>
    $userInfoChars = "(?:[a-zA-Z0-9._~!$&'()*+,;=:-]|%[0-9a-fA-F]{2})"
    return "(?<UserInfo>$userInfoChars*@)?"
}
