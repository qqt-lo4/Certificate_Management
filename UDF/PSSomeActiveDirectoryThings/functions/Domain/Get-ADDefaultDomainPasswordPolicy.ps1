function Get-ADDefaultDomainPasswordPolicy {
    <#
    .SYNOPSIS
        Returns the default password and account lockout policy for an AD domain.

    .DESCRIPTION
        Queries the domain head object via LDAP to retrieve the Default Domain
        Password Policy and account lockout settings. These attributes are stored
        directly on the domain root (e.g., DC=contoso,DC=com).

        Returned time-span properties (maxPwdAge, minPwdAge, lockoutDuration,
        lockoutObservationWindow) are converted from AD large-integer ticks to
        TimeSpan objects. A zero or max-value duration is returned as TimeSpan.Zero.

    .PARAMETER Server
        Domain FQDN or domain controller to query. Defaults to the current
        user's domain ($env:USERDNSDOMAIN).

    .PARAMETER Credential
        Optional PSCredential for authentication.

    .OUTPUTS
        PSCustomObject with the following properties:
            Domain, MinPasswordLength, PasswordHistoryCount, ComplexityEnabled,
            ReversibleEncryptionEnabled, MaxPasswordAge, MinPasswordAge,
            LockoutThreshold, LockoutDuration, LockoutObservationWindow.

    .EXAMPLE
        Get-ADDefaultDomainPasswordPolicy

    .EXAMPLE
        Get-ADDefaultDomainPasswordPolicy -Server "child.contoso.com"

    .EXAMPLE
        Get-CurrentADForestDomains | ForEach-Object {
            Get-ADDefaultDomainPasswordPolicy -Server $_.Name
        }

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        1.0.0 (2026-04-12) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [string]$Server = $env:USERDNSDOMAIN,

        [AllowNull()]
        [PSCredential]$Credential
    )

    Process {
        # Resolve the domain DN via RootDSE
        $sRootDSEPath = if ($Server) { "LDAP://$Server/RootDSE" } else { "LDAP://RootDSE" }
        $oRootDSE = Get-DirectoryEntry -Path $sRootDSEPath -Credential $Credential
        $sDomainDN = $oRootDSE.Properties["defaultNamingContext"][0].ToString()

        # Query the domain head object for password policy attributes
        $sLdapPath = if ($Server) { "LDAP://$Server/$sDomainDN" } else { "LDAP://$sDomainDN" }
        $oDomainDE = Get-DirectoryEntry -Path $sLdapPath -Credential $Credential

        $aProperties = @(
            'minPwdLength', 'pwdHistoryLength', 'pwdProperties',
            'maxPwdAge', 'minPwdAge',
            'lockoutThreshold', 'lockoutDuration', 'lockOutObservationWindow'
        )

        $oSearcher = New-Object System.DirectoryServices.DirectorySearcher($oDomainDE)
        $oSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Base
        $oSearcher.Filter = "(objectClass=domain)"
        foreach ($sProp in $aProperties) {
            $oSearcher.PropertiesToLoad.Add($sProp) | Out-Null
        }

        $oResult = $oSearcher.FindOne()
        if (-not $oResult) {
            throw "Could not retrieve password policy for domain: $sDomainDN"
        }

        $hProps = $oResult.Properties

        # pwdProperties is a bitmask: bit 0 = DOMAIN_PASSWORD_COMPLEX
        $iPwdProperties = [int]$hProps['pwdproperties'][0]
        $bComplexity = ($iPwdProperties -band 1) -ne 0
        # bit 4 = DOMAIN_PASSWORD_STORE_CLEARTEXT (reversible encryption)
        $bReversible = ($iPwdProperties -band 16) -ne 0

        [PSCustomObject][ordered]@{
            Domain                      = $sDomainDN
            MinPasswordLength           = [int]$hProps['minpwdlength'][0]
            PasswordHistoryCount        = [int]$hProps['pwdhistorylength'][0]
            ComplexityEnabled           = $bComplexity
            ReversibleEncryptionEnabled = $bReversible
            MaxPasswordAge              = Convert-ADTimeSpan -Value $hProps['maxpwdage'][0]
            MinPasswordAge              = Convert-ADTimeSpan -Value $hProps['minpwdage'][0]
            LockoutThreshold            = [int]$hProps['lockoutthreshold'][0]
            LockoutDuration             = Convert-ADTimeSpan -Value $hProps['lockoutduration'][0]
            LockoutObservationWindow    = Convert-ADTimeSpan -Value $hProps['lockoutobservationwindow'][0]
        }
    }
}
