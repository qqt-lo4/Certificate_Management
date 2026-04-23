function Get-ADFineGrainedPasswordPolicy {
    <#
    .SYNOPSIS
        Returns Fine-Grained Password Policies (PSOs) defined in an AD domain.

    .DESCRIPTION
        Queries the Password Settings Container (CN=Password Settings Container,
        CN=System,<domainDN>) for msDS-PasswordSettings objects. These objects
        allow per-group or per-user password and lockout policies that override
        the Default Domain Password Policy.

        Each PSO includes its precedence, password rules, lockout settings, and
        the list of users/groups it applies to (msDS-PSOAppliesTo).

    .PARAMETER Filter
        LDAP filter to apply within the Password Settings Container.
        Defaults to "(objectClass=msDS-PasswordSettings)" which returns all PSOs.

    .PARAMETER Server
        Domain FQDN or domain controller to query. Defaults to the current
        user's domain ($env:USERDNSDOMAIN).

    .PARAMETER Credential
        Optional PSCredential for authentication.

    .OUTPUTS
        PSCustomObject[] with properties:
            Name, Precedence, MinPasswordLength, PasswordHistoryCount,
            ComplexityEnabled, ReversibleEncryptionEnabled, MaxPasswordAge,
            MinPasswordAge, LockoutThreshold, LockoutDuration,
            LockoutObservationWindow, AppliesTo.

    .EXAMPLE
        Get-ADFineGrainedPasswordPolicy

    .EXAMPLE
        Get-ADFineGrainedPasswordPolicy -Server "child.contoso.com"

    .EXAMPLE
        Get-CurrentADForestDomains | ForEach-Object {
            Get-ADFineGrainedPasswordPolicy -Server $_.Name
        }

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        1.0.0 (2026-04-12) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [string]$Filter = "(objectClass=msDS-PasswordSettings)",

        [string]$Server = $env:USERDNSDOMAIN,

        [AllowNull()]
        [PSCredential]$Credential
    )

    Process {
        # Resolve the domain DN via RootDSE
        $sRootDSEPath = if ($Server) { "LDAP://$Server/RootDSE" } else { "LDAP://RootDSE" }
        $oRootDSE = Get-DirectoryEntry -Path $sRootDSEPath -Credential $Credential
        $sDomainDN = $oRootDSE.Properties["defaultNamingContext"][0].ToString()

        # Password Settings Container path
        $sPSOContainerDN = "CN=Password Settings Container,CN=System,$sDomainDN"
        $sLdapPath = if ($Server) { "LDAP://$Server/$sPSOContainerDN" } else { "LDAP://$sPSOContainerDN" }

        $oPSOContainerDE = Get-DirectoryEntry -Path $sLdapPath -Credential $Credential

        $aProperties = @(
            'name', 'msDS-PasswordSettingsPrecedence',
            'msDS-MinimumPasswordLength', 'msDS-PasswordHistoryLength',
            'msDS-PasswordComplexityEnabled', 'msDS-PasswordReversibleEncryptionEnabled',
            'msDS-MaximumPasswordAge', 'msDS-MinimumPasswordAge',
            'msDS-LockoutThreshold', 'msDS-LockoutDuration', 'msDS-LockoutObservationWindow',
            'msDS-PSOAppliesTo'
        )

        $oSearcher = New-Object System.DirectoryServices.DirectorySearcher($oPSOContainerDE)
        $oSearcher.SearchScope = [System.DirectoryServices.SearchScope]::OneLevel
        $oSearcher.Filter = $Filter
        foreach ($sProp in $aProperties) {
            $oSearcher.PropertiesToLoad.Add($sProp) | Out-Null
        }

        $aResults = $oSearcher.FindAll()

        foreach ($oResult in $aResults) {
            $hProps = $oResult.Properties

            # msDS-PSOAppliesTo is a multi-valued DN attribute
            $aAppliesTo = @()
            if ($hProps['msds-psoappliesTo']) {
                $aAppliesTo = @($hProps['msds-psoappliesTo'] | ForEach-Object { $_.ToString() })
            }

            [PSCustomObject][ordered]@{
                Name                        = $hProps['name'][0].ToString()
                Precedence                  = [int]$hProps['msds-passwordsettingsprecedence'][0]
                MinPasswordLength           = [int]$hProps['msds-minimumpasswordlength'][0]
                PasswordHistoryCount        = [int]$hProps['msds-passwordhistorylength'][0]
                ComplexityEnabled           = [bool][int]$hProps['msds-passwordcomplexityenabled'][0]
                ReversibleEncryptionEnabled = [bool][int]$hProps['msds-passwordreversibleencryptionenabled'][0]
                MaxPasswordAge              = Convert-ADTimeSpan -Value $hProps['msds-maximumpasswordage'][0]
                MinPasswordAge              = Convert-ADTimeSpan -Value $hProps['msds-minimumpasswordage'][0]
                LockoutThreshold            = [int]$hProps['msds-lockoutthreshold'][0]
                LockoutDuration             = Convert-ADTimeSpan -Value $hProps['msds-lockoutduration'][0]
                LockoutObservationWindow    = Convert-ADTimeSpan -Value $hProps['msds-lockoutobservationwindow'][0]
                AppliesTo                   = $aAppliesTo
            }
        }
    }
}
