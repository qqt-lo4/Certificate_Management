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

    .PARAMETER FilterTargets
        Optional list of distinguished names. When set in -Recursive
        mode, the discovered container list is intersected with this
        set BEFORE the per-container GPO fetch + GptTmpl.inf parse
        runs. Used by scoped audit exports to skip GPOs linked to
        out-of-scope OUs (DCs, PAW, unrelated business units, ...)
        and shave the heavy fetch / parse cost from those branches.
        DNs are compared case-insensitively.

    .PARAMETER Server
        Domain FQDN or domain controller to query. Defaults to $env:USERDNSDOMAIN.

    .PARAMETER Credential
        Optional PSCredential for authentication.

    .OUTPUTS
        PSCustomObject[] with properties:
            LinkedTo, DisplayName, GPOId, LinkOrder, LinkEnabled,
            LinkEnforced, GPCFileSysPath, WMIFilter, GPOStatus,
            SecuritySettingsCount, SecuritySettings.
        WMIFilter holds the display name of the msWMI-Som object referenced
        by gPCWQLFilter, or $null when no filter is attached.
        GPOStatus reflects the GPO-object-level 'flags' attribute (distinct
        from per-link LinkEnabled): 'Enabled' (flags=0) / 'UserDisabled'
        (flags=1) / 'ComputerDisabled' (flags=2) / 'AllDisabled' (flags=3).
        Mapping per MS-GPOL section 2.2.4.

    .EXAMPLE
        Get-ADGroupPolicyLinkSecuritySettings

    .EXAMPLE
        Get-ADGroupPolicyLinkSecuritySettings -Server child.contoso.com

    .EXAMPLE
        Get-ADGroupPolicyLinkSecuritySettings | Where-Object SecuritySettingsCount -gt 0

    .NOTES
        Author  : Loïc Ade
        Version : 1.1.0

        1.1.0 (2026-06-04, Loic Ade) - Add -FilterTargets [string[]]
                             optional pre-filter applied after the
                             -Recursive gPLink discovery. Used by
                             scoped audit reports (perimeter OU
                             ancestors) so the heavy per-container
                             GPO fetch + GptTmpl.inf parse only
                             runs on perimeter-applicable OUs.

        1.0.0 (2026-04-13) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [string]$Target,

        [switch]$Recursive,

        # Scoped audit support: intersect the discovered container
        # list with this set before paying the per-container GPO
        # fetch + GptTmpl.inf parse. Case-insensitive DN compare.
        [string[]]$FilterTargets,

        [string]$Server = $env:USERDNSDOMAIN,

        [AllowNull()]
        [PSCredential]$Credential,

        [AllowNull()]
        [System.Management.Automation.Runspaces.PSSession]$Session
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

            # Optional perimeter filter: drop discovered containers
            # that aren't in the audit scope so we don't pay the
            # GPO-fetch + GptTmpl parse cost for OUs the caller
            # has already determined are out of perimeter.
            if ($FilterTargets) {
                $hFilter = @{}
                foreach ($t in $FilterTargets) {
                    if ($t) { $hFilter[([string]$t).ToUpperInvariant()] = $true }
                }
                $iBefore = $aTargets.Count
                $aTargets = @($aTargets | Where-Object { $hFilter.ContainsKey(([string]$_).ToUpperInvariant()) })
                Write-Verbose "Get-ADGroupPolicyLinkSecuritySettings : FilterTargets kept $($aTargets.Count)/$iBefore container(s)"
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

            # 'name' is the GPO's CN (the {GUID}); needed by callers that join
            # link records to GPO-object lookups (e.g., per-GPO DACL maps for
            # Empty-Filtering checks). Without it, $oLink.name is $null.
            $aGPOLinks = @(Get-ADGroupPolicyLink @hParams -Properties 'name', 'displayName', 'gPCFileSysPath', 'gPCWQLFilter', 'flags')

            foreach ($oLink in $aGPOLinks) {
                $sFileSysPath = $oLink.gPCFileSysPath
                $aSettings = @()

                if ($sFileSysPath) {
                    $hSecParams = @{ GPCFileSysPath = $sFileSysPath }
                    if ($Credential) { $hSecParams['Credential'] = $Credential }
                    if ($Session)    { $hSecParams['Session']    = $Session }
                    $aSettings = @(Get-ADGroupPolicySecuritySettings @hSecParams)
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

                # GPO-object-level 'flags' (distinct from per-link LinkEnabled).
                # Per MS-GPOL section 2.2.4:
                #   0 = all enabled, 1 = user config disabled,
                #   2 = computer config disabled, 3 = all settings disabled.
                # Null/missing flags is treated as 0 (Enabled) - the legacy
                # default when the attribute is unset.
                $iGPOFlags = 0
                try { if ($null -ne $oLink.flags) { $iGPOFlags = [int]$oLink.flags } } catch {}
                $sGPOStatus = switch ($iGPOFlags) {
                    0       { 'Enabled' }
                    1       { 'UserDisabled' }
                    2       { 'ComputerDisabled' }
                    3       { 'AllDisabled' }
                    default { "Unknown ($iGPOFlags)" }
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
                    GPOStatus             = $sGPOStatus
                    SecuritySettingsCount = $aSettings.Count
                    SecuritySettings      = $aSettings
                }
            }
        }
    }
}
