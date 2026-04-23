function Get-ADGroupPolicyLink {
    <#
    .SYNOPSIS
        Returns the Group Policy links configured on an AD container.

    .DESCRIPTION
        Reads the gPLink attribute from the specified container (domain root,
        OU, or site) and parses it into ordered GPO link objects.

        The gPLink attribute stores links as a sequence of
        [LDAP://CN={GUID},CN=Policies,CN=System,<domainDN>;status] entries
        where status is a bitmask: bit 0 = disabled, bit 1 = enforced.

        Each linked GPO is resolved via Get-ADGroupPolicy. The returned objects
        contain all resolved GPO properties plus link-specific properties
        (LinkOrder, LinkEnabled, LinkEnforced, GPDN).

        Links are returned in link order (highest priority first, which is
        the reverse of the stored order in gPLink).

    .PARAMETER Target
        The distinguished name of the container to read. When omitted,
        defaults to the domain root.

    .PARAMETER Properties
        Properties to load from each GPO object. Passed through to
        Get-ADGroupPolicy. When omitted, returns the default property set.

    .PARAMETER Server
        Domain FQDN or domain controller to query. Defaults to $env:USERDNSDOMAIN.

    .PARAMETER Credential
        Optional PSCredential for authentication.

    .OUTPUTS
        Custom AD groupPolicyContainer objects enriched with:
            LinkOrder, LinkEnabled, LinkEnforced, GPDN.

    .EXAMPLE
        Get-ADGroupPolicyLink

    .EXAMPLE
        Get-ADGroupPolicyLink -Properties 'displayName', 'gPCFileSysPath'

    .EXAMPLE
        Get-ADGroupPolicyLink -Target "OU=Workstations,DC=contoso,DC=com"

    .EXAMPLE
        Get-ADGroupPolicyLink -Server child.contoso.com

    .NOTES
        Author  : Loïc Ade
        Version : 1.2.0

        1.2.0 (2026-04-13) - Resolve GPO via direct LDAP path on parsed GPDN
                             so cross-domain links return real displayName
                             instead of falling back to the GPO GUID
        1.1.0 (2026-04-12) - Resolve full GPO objects; add Properties parameter
        1.0.0 (2026-04-12) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [string]$Target,

        [string[]]$Properties,

        [string]$Server = $env:USERDNSDOMAIN,

        [AllowNull()]
        [PSCredential]$Credential
    )

    Process {
        # Resolve domain DN if no target specified
        if (-not $Target) {
            $sRootDSEPath = if ($Server) { "LDAP://$Server/RootDSE" } else { "LDAP://RootDSE" }
            $oRootDSE = Get-DirectoryEntry -Path $sRootDSEPath -Credential $Credential
            $Target = $oRootDSE.Properties["defaultNamingContext"][0].ToString()
        }

        # Read gPLink from the target container
        $sLdapPath = if ($Server) { "LDAP://$Server/$Target" } else { "LDAP://$Target" }
        $oTargetDE = Get-DirectoryEntry -Path $sLdapPath -Credential $Credential

        $sGPLink = $oTargetDE.Properties["gPLink"]
        if (-not $sGPLink) { return }
        $sGPLink = $sGPLink.ToString()

        # Parse gPLink: "[LDAP://cn={GUID},...;status][LDAP://...;status]"
        # Stored order is lowest priority first; reverse for link order
        $aMatches = [regex]::Matches($sGPLink, '\[([^;]+);(\d+)\]')
        if ($aMatches.Count -eq 0) { return }

        $aParsedLinks = @()
        foreach ($oMatch in $aMatches) {
            $sGPDN = $oMatch.Groups[1].Value -replace '^LDAP://', ''
            $iStatus = [int]$oMatch.Groups[2].Value

            # Extract GUID from DN: CN={xxxxxxxx-...},CN=Policies,...
            $sGPOId = ""
            if ($sGPDN -match 'CN=(\{[0-9a-fA-F\-]+\})') {
                $sGPOId = $Matches[1]
            }

            $aParsedLinks += @{
                GPOId       = $sGPOId
                LinkEnabled = -not ($iStatus -band 1)
                LinkEnforced = [bool]($iStatus -band 2)
                GPDN        = $sGPDN
            }
        }

        # Reverse for link order (first = highest priority)
        [array]::Reverse($aParsedLinks)

        # Resolve GPO objects and enrich with link properties.
        # Path-based binding cannot take -Server (the server is embedded in the
        # LDAP path itself), so only Credential / Properties are forwarded.
        $hADParams = @{}
        if ($Credential) { $hADParams['Credential'] = $Credential }
        if ($Properties) { $hADParams['Properties'] = $Properties }

        $iLinkOrder = 1
        foreach ($hLink in $aParsedLinks) {
            $oGPO = $null
            if ($hLink.GPDN) {
                # Cross-domain links: the GPO can live in a different domain
                # than the container holding the gPLink. Extract the target
                # domain from the parsed DN (DC=foo,DC=bar -> foo.bar) and
                # bind there instead of the current $Server.
                $sTargetServer = $null
                if ($hLink.GPDN -match '((?:DC=[^,]+,?)+)$') {
                    $sTargetServer = ($Matches[1] -replace 'DC=', '' -replace ',', '.').TrimEnd('.')
                }
                if (-not $sTargetServer) { $sTargetServer = $Server }

                $sGPOPath = if ($sTargetServer) { "LDAP://$sTargetServer/$($hLink.GPDN)" } else { "LDAP://$($hLink.GPDN)" }
                try {
                    $oGPO = Get-ADGroupPolicy -Path $sGPOPath @hADParams
                } catch {
                    Write-Warning "Get-ADGroupPolicyLink : Could not resolve GPO at $sGPOPath - $_"
                }
            }

            if ($oGPO) {
                # Get-ADObject returns an OrderedDictionary — use the indexer
                # so new keys can be added (dot-notation assignment would throw
                # PropertyNotFound for keys that don't already exist).
                $oGPO['LinkOrder']    = $iLinkOrder
                $oGPO['LinkEnabled']  = $hLink.LinkEnabled
                $oGPO['LinkEnforced'] = $hLink.LinkEnforced
                $oGPO['GPDN']         = $hLink.GPDN
                $oGPO
            } else {
                # Fallback if GPO object could not be resolved
                [PSCustomObject][ordered]@{
                    displayname  = $hLink.GPOId
                    name         = $hLink.GPOId
                    LinkOrder    = $iLinkOrder
                    LinkEnabled  = $hLink.LinkEnabled
                    LinkEnforced = $hLink.LinkEnforced
                    GPDN         = $hLink.GPDN
                }
            }

            $iLinkOrder++
        }
    }
}
