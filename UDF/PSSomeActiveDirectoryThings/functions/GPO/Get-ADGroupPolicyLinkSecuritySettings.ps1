function Get-ADGroupPolicyLinkSecuritySettings {
    <#
    .SYNOPSIS
        Collects security settings from all GPOs linked to an AD container.

    .DESCRIPTION
        Retrieves GPO links on the specified container (domain root by default),
        then parses the GptTmpl.inf security template of each linked GPO.

        Returns one object per linked GPO containing link metadata, GPO display
        name, the count of security settings found, and the parsed settings
        array. GPOs without a security template return a SecuritySettingsCount
        of 0 and an empty SecuritySettings array.

    .PARAMETER Target
        The distinguished name of the container to read. When omitted,
        defaults to the domain root. Ignored when -Recursive is specified.

    .PARAMETER Recursive
        When set, discovers every container in the domain that has a
        gPLink attribute and returns links from all of them. Use this to
        include GPOs linked at OU level, not just at the domain root.

    .PARAMETER Server
        Domain FQDN or domain controller to query. Defaults to $env:USERDNSDOMAIN.

    .PARAMETER Credential
        Optional PSCredential for authentication.

    .OUTPUTS
        PSCustomObject[] with properties:
            LinkedTo, DisplayName, GPOId, LinkOrder, LinkEnabled,
            LinkEnforced, GPCFileSysPath, WMIFilter,
            SecuritySettingsCount, SecuritySettings.
        WMIFilter holds the display name of the msWMI-Som object referenced
        by gPCWQLFilter, or $null when no filter is attached.

    .EXAMPLE
        Get-ADGroupPolicyLinkSecuritySettings

    .EXAMPLE
        Get-ADGroupPolicyLinkSecuritySettings -Server child.contoso.com

    .EXAMPLE
        Get-ADGroupPolicyLinkSecuritySettings | Where-Object SecuritySettingsCount -gt 0

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        1.0.0 (2026-04-13) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [string]$Target,

        [switch]$Recursive,

        [string]$Server = $env:USERDNSDOMAIN,

        [AllowNull()]
        [PSCredential]$Credential
    )

    Process {
        # Per-invocation cache: a WMI filter shared across many GPOs is
        # fetched once and reused for every link that references it.
        $hWMIFilterCache = @{}

        # Build the list of containers to scan
        $aTargets = @()
        if ($Recursive) {
            # Search the whole domain for any container holding a gPLink
            $sRootDSEPath = if ($Server) { "LDAP://$Server/RootDSE" } else { "LDAP://RootDSE" }
            $oRootDSE = Get-DirectoryEntry -Path $sRootDSEPath -Credential $Credential
            $sDomainDN = $oRootDSE.Properties["defaultNamingContext"][0].ToString()

            $hSearchParams = @{
                LDAPFilter = '(gPLink=*)'
                SearchBase = $sDomainDN
                SearchScope = 'Subtree'
                Properties = @('distinguishedName', 'gPLink')
            }
            if ($Server) { $hSearchParams['Server'] = $Server }
            if ($Credential) { $hSearchParams['Credential'] = $Credential }

            $aContainers = @(Get-ADObject @hSearchParams)
            foreach ($oCont in $aContainers) {
                $aTargets += $oCont.distinguishedname
            }
        } else {
            $sLinkedTo = $Target
            if (-not $sLinkedTo) {
                $sRootDSEPath = if ($Server) { "LDAP://$Server/RootDSE" } else { "LDAP://RootDSE" }
                $oRootDSE = Get-DirectoryEntry -Path $sRootDSEPath -Credential $Credential
                $sLinkedTo = $oRootDSE.Properties["defaultNamingContext"][0].ToString()
            }
            $aTargets = @($sLinkedTo)
        }

        foreach ($sLinkedTo in $aTargets) {
            $hParams = @{ Target = $sLinkedTo }
            if ($Server) { $hParams['Server'] = $Server }
            if ($Credential) { $hParams['Credential'] = $Credential }

            $aGPOLinks = @(Get-ADGroupPolicyLink @hParams -Properties 'displayName', 'gPCFileSysPath', 'gPCWQLFilter')

            foreach ($oLink in $aGPOLinks) {
                $sFileSysPath = $oLink.gPCFileSysPath
                $aSettings = @()

                if ($sFileSysPath) {
                    $aSettings = @(Get-ADGroupPolicySecuritySettings -GPCFileSysPath $sFileSysPath)
                }

                # Resolve WMI filter display name, cache results per invocation
                # so shared filters only hit AD once.
                $sWMIFilter = $null
                $sFilterRef = $oLink.gpcwqlfilter
                if ($sFilterRef) {
                    if ($hWMIFilterCache.ContainsKey($sFilterRef)) {
                        $sWMIFilter = $hWMIFilterCache[$sFilterRef]
                    } else {
                        $hWMIParams = @{ Id = $sFilterRef }
                        if ($Server) { $hWMIParams['Server'] = $Server }
                        if ($Credential) { $hWMIParams['Credential'] = $Credential }
                        $oFilter = Get-ADWMIFilter @hWMIParams
                        $sWMIFilter = if ($oFilter) { $oFilter.Name } else { $null }
                        $hWMIFilterCache[$sFilterRef] = $sWMIFilter
                    }
                }

                [PSCustomObject][ordered]@{
                    LinkedTo              = $sLinkedTo
                    DisplayName           = $oLink.displayname
                    GPOId                 = $oLink.name
                    LinkOrder             = $oLink.LinkOrder
                    LinkEnabled           = $oLink.LinkEnabled
                    LinkEnforced          = $oLink.LinkEnforced
                    GPCFileSysPath        = $sFileSysPath
                    WMIFilter             = $sWMIFilter
                    SecuritySettingsCount = $aSettings.Count
                    SecuritySettings      = $aSettings
                }
            }
        }
    }
}
