function Export-ADSecurityReport {
    <#
    .SYNOPSIS
        Exports Active Directory security evidence (password & lockout policy,
        OU statistics, GPO catalog with hardening match, WMI filters) into a
        navigable HTML report.

    .DESCRIPTION
        For every domain of the current forest, collects:
          - Default Password & Lockout Policy
          - Fine-Grained Password Policies (PSOs)
          - OU Statistics (users/computers, direct & recursive, with disabled
            counterparts) - feeds the Dead-GPO Empty-Target check
          - GPO Links per domain + per-GPO Filtered Settings panels:
            Restricted Groups / GPP Local Groups (CMMC AC.L2-3.1.5),
            LAPS settings, Audit / Privilege Rights, Registry policies
            cross-checked against Get-ADHardeningCatalog, Scheduled Tasks,
            Network Profiles, ...
          - Forest-wide WMI Filters list (with per-domain usage counters)

        Extracted from the legacy Export-ADConfiguration so the security
        slice ships as a focused standalone report, decoupled from the
        group catalogues (Export-ADGroupReport), the NTP evidence
        (Export-ADTimeReport), and the Varonis lockout events
        (Export-VaronisReport).

    .PARAMETER FolderPath
        Local destination folder for the HTML report. Must exist.

    .PARAMETER Server
        Optional AD server / domain hint. When omitted, every domain of the
        current forest is enumerated.

    .PARAMETER Credential
        Optional credentials for AD queries.

    .PARAMETER PSRemoting
        When set, opens a PSSession per domain so every SYSVOL read
        (GptTmpl.inf, registry.pol, Groups.xml, ScheduledTasks.xml, ...)
        runs under the remote DC's identity. Fixes the "calling account
        is filtered by the GPO ACL" case: a domain admin can read GPOs that
        the local export user cannot.

    .PARAMETER Perimeter
        Hashtable mapping perimeter name -> array of "DOMAIN\Name"
        identity tokens (NetBIOS or DNS-form prefix; both are
        accepted by Resolve-ADObject). Example:
            @{
                Biomedical = @('CORP\jdoe','CORP\PC-001')
                Filers     = @('CORP\FILER01','CORP\FILER02')
            }
        Each key drives a dedicated tab in the report carrying that
        perimeter's per-domain security view (Default Password Policy,
        PSO, OU Stats, GPO Links filtered to OUs touching that
        perimeter, WMI Filters). The global Inventory tab carries one
        sub-section per (perimeter, objectclass) pair so users and
        computers stay in their own column-typed tables. The global
        GPO Catalog tab keeps the cross-domain dedup'ed per-GPO
        panels and the forest-wide WMI list.

        When -Perimeter is omitted or empty, the function runs in
        unscoped mode: every forest domain is walked end-to-end,
        sections land in a single "security" tab and no perimeter
        filtering is applied.

    .OUTPUTS
        [System.IO.FileInfo] - the generated HTML file.

    .EXAMPLE
        # Unscoped: every domain, single Security tab.
        Export-ADSecurityReport -FolderPath C:\Exports

    .EXAMPLE
        # Multi-perimeter: one tab per perimeter + global Inventory + GPO.
        $hPerim = [ordered]@{
            Biomedical = $cmmcIdentities
            Filers     = $filerIdentities
        }
        Export-ADSecurityReport -FolderPath C:\Exports `
            -Perimeter $hPerim -Credential $oCred -PSRemoting

    .NOTES
        Author  : Loic Ade
        Version : 2.0.0

        2.0.0 (2026-06-12, Loic Ade) - Multi-perimeter support: the
                             -Identity / -ScopeName param pair is
                             replaced by -Perimeter [hashtable]
                             (PerimName -> identity tokens). Each
                             perimeter drives its own Security tab;
                             the Inventory tab is global and carries
                             per-perimeter sub-sections split per
                             objectclass; GPO Catalog stays global.
                             Per-domain AD queries are cached so two
                             perimeters sharing a domain do not pay
                             the round-trip twice.
        1.0.0 (2026-06-03, Loic Ade) - Initial version. Extracted from the
                             legacy Export-ADConfiguration (Project_UDF).
                             AD-only evidence (security policies + GPO
                             catalog + perimeter inventory). Group catalogs,
                             NTP evidence, and Varonis lockout logs ship in
                             their own dedicated reports
                             (Export-ADGroupReport, Export-ADTimeReport,
                             Export-VaronisReport).
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$FolderPath,

        [string]$Server,

        [PSCredential]$Credential,

        # When set, opens a PSSession per domain (host = the domain FQDN, which
        # resolves to a DC; credentials reuse -Credential) and delegates every
        # SYSVOL file read (GptTmpl.inf, registry.pol, Groups.xml) inside that
        # session via Invoke-Command. The remote machine's identity then reads
        # the files, which fixes the "calling account is filtered by the GPO
        # ACL" case: a domain admin can read GPOs that the local export user
        # cannot.
        [switch]$PSRemoting,

        # Multi-perimeter scope. Hashtable PerimName -> string[] of
        # "DOMAIN\Name" identity tokens (NetBIOS or DNS-form prefix).
        # See the .PARAMETER help section for the shape and behaviour.
        # Empty / omitted = unscoped (every domain, single Security
        # tab, no perimeter filtering).
        [hashtable]$Perimeter
    )

    Begin {
        if (-not (Test-Path $FolderPath -PathType Container)) {
            throw "Folder does not exist: $FolderPath"
        }
    }

    Process {
        # Always-on flags (this report unconditionally produces
        # security + inventory + GPO content; Time/Groups live in
        # their own dedicated reports).
        $IncludeSecurityPolicies   = $true
        $IncludeTimeSynchronization = $false

        # Multi-perim mode is the only mode now; unscoped reports
        # synthesise a single "Security" pseudo-perim covering the
        # whole forest (no identity restriction, no GPO Links
        # filtering, single security tab).
        $bScoped = $Perimeter -and $Perimeter.Count -gt 0

        # Wall-clock measurement of the full Process block. Local to
        # this invocation: each call to the cmdlet (and there's one
        # call per checked export type) creates its own Stopwatch, so
        # the AD/BeyondTrust/Filer reports each get their own
        # independent duration tooltip in their respective HTML files.
        # Read just before New-HTMLReport so the tooltip captures the
        # full data-collection cost.
        $oSW = [System.Diagnostics.Stopwatch]::StartNew()

        $sTimestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $sFileName  = "Export_AD_Security_${sTimestamp}.html"
        $sFilePath  = Join-Path $FolderPath $sFileName
        $sCallerName = "Exporting AD Security"

        $iTotal = 0
        $iTocIndex = 0
        $aSectionFiles = @()
        $aTabs = @()

        # --- Progress phases ------------------------------------------------
        # Single source of truth for Write-Progress percentages. The export
        # is split into monotone phases whose widths reflect roughly how
        # long each phase tends to take. Sub-progress within a phase is
        # passed as 0..1 to Get-PhaseProgress; per-domain sub-phases use
        # Get-DomainStepProgress which carves the phase into equal slices
        # (one per domain) and computes the position inside the slice.
        #     Phase 1 - Groups               :   0 ..  20 %
        #     Phase 2 - Security per domain  :  20 ..  65 %
        #         Within domain slice:
        #             0.00  Default Password Policy
        #             0.05  Fine-Grained Password (PSO)
        #             0.15  OU Statistics
        #             0.40  GPO Links & Security (now also fetches per-GPO
        #                   DACLs to compute hasSecurityFilter and the
        #                   per-link reachableEnabled audience)
        #     Phase 3 - WMI Filters          :  65 ..  93 %
        #     Phase 4 - HTML Generation      :  93 ..  99 %
        function Get-PhaseProgress {
            Param([double]$Start, [double]$End, [double]$Sub)
            return [int]($Start + ($End - $Start) * $Sub)
        }
        function Get-DomainStepProgress {
            Param([int]$Idx, [int]$Count, [double]$Start, [double]$End, [double]$Step)
            if ($Count -lt 1) { return [int]$Start }
            $dSliceStart = $Start + (($Idx - 1) / $Count) * ($End - $Start)
            $dSliceEnd   = $Start + ($Idx / $Count) * ($End - $Start)
            return [int]($dSliceStart + ($dSliceEnd - $dSliceStart) * $Step)
        }

        # --- Common AD params ---
        $hADBaseParams = @{}
        if ($Server) { $hADBaseParams['Server'] = $Server }
        if ($Credential) { $hADBaseParams['Credential'] = $Credential }

        # --- CMMC control mapping for GPO / policy settings ---
        # Returns the CMMC control code associated with a given setting name
        # (or section, when the mapping applies to all settings of a category),
        # or $null when the entry is not in scope for any tracked control.
        function Get-CMMCControl {
            Param(
                [string]$Setting,
                [string]$Section
            )

            # Section-driven mappings: apply uniformly to every setting of
            # the named section (used when the setting name itself is not
            # standardized — e.g., a SID-suffixed Group Membership key).
            if ($Section) {
                switch -Regex ($Section) {
                    '^(Group Membership|Restricted Groups|GPP - Local Group Membership)$' {
                        return 'AC.L2-3.1.5 - LEAST PRIVILEGE'
                    }
                }
            }

            switch -Regex ($Setting) {
                # AC.L2-3.1.8 - UNSUCCESSFUL LOGON ATTEMPTS (account lockout)
                '^(LockoutBadCount|LockoutDuration|ResetLockoutCount|lockoutThreshold|lockoutDuration|lockoutObservationWindow|Account Lockout Threshold|Account Lockout Duration|Lockout Observation Window)$' {
                    return 'AC.L2-3.1.8 - UNSUCCESSFUL LOGON ATTEMPTS'
                }
                # AC.L2-3.1.10 - SESSION LOCK (screen saver / inactivity lock)
                '^(ScreenSaveActive|ScreenSaverIsSecure|ScreenSaveTimeOut|InactivityTimeoutSecs)$' {
                    return 'AC.L2-3.1.10 - SESSION LOCK'
                }
                # Also catch the full registry key path form of InactivityTimeoutSecs
                'InactivityTimeoutSecs$' {
                    return 'AC.L2-3.1.10 - SESSION LOCK'
                }
                # IA.L2-3.5.8 - PASSWORD REUSE
                # History size is the primary control; max/min age are
                # supporting controls (forced rotation + anti-cycling).
                '^(PasswordHistorySize|passwordHistoryCount|Password History Count|MaximumPasswordAge|maxPasswordAge|Maximum Password Age|MinimumPasswordAge|minPasswordAge|Minimum Password Age)$' {
                    return 'IA.L2-3.5.8 - PASSWORD REUSE'
                }
                # IA.L2-3.5.7 - PASSWORD COMPLEXITY (LAPS-managed local admin)
                '^(PasswordComplexity|PasswordLength)$' {
                    return 'IA.L2-3.5.7 - PASSWORD COMPLEXITY'
                }
                # IA.L2-3.5.8 - PASSWORD REUSE (LAPS rotation + history)
                '^(PasswordAgeDays|PasswordHistoryLength)$' {
                    return 'IA.L2-3.5.8 - PASSWORD REUSE'
                }
                # IA.L2-3.5.10 - CRYPTOGRAPHICALLY-PROTECTED PASSWORDS
                # LAPS encrypts the password before writing it to AD; backup
                # directory + encryption flags govern whether protection is on.
                '^(EncryptionEnabled|ADPasswordEncryptionEnabled|ADPasswordEncryptionPrincipal|BackupDirectory)$' {
                    return 'IA.L2-3.5.10 - CRYPTOGRAPHICALLY-PROTECTED PASSWORDS'
                }
                # AC.L2-3.1.5 - LEAST PRIVILEGE (LAPS managed account name)
                '^(AdminAccountName|AdministratorAccountName)$' {
                    return 'AC.L2-3.1.5 - LEAST PRIVILEGE'
                }
            }
            return $null
        }

        # Well-known privileged local group SIDs. Used by the rendering layer
        # to filter Restricted Groups / GPP entries to administrator-equivalent
        # groups only. The module-level extraction returns ALL groups; this
        # list is the audit scope for CMMC AC.L2-3.1.5 / 3.1.6 / 3.1.7.
        $aPrivilegedLocalGroupSids = @(
            'S-1-5-32-544'  # Administrators
            'S-1-5-32-547'  # Power Users (deprecated)
            'S-1-5-32-548'  # Account Operators (DC)
            'S-1-5-32-551'  # Backup Operators
            'S-1-5-32-555'  # Remote Desktop Users
            'S-1-5-32-562'  # Distributed COM Users
            'S-1-5-32-578'  # Hyper-V Administrators
            'S-1-5-32-580'  # Remote Management Users
        )
        # Fallback when the SID is missing (e.g., name-only Restricted Groups
        # entries) — match against the resolved/declared group name.
        $aPrivilegedLocalGroupNames = @(
            'Administrators', 'BUILTIN\Administrators',
            'Power Users', 'BUILTIN\Power Users',
            'Account Operators', 'BUILTIN\Account Operators',
            'Backup Operators', 'BUILTIN\Backup Operators',
            'Remote Desktop Users', 'BUILTIN\Remote Desktop Users',
            'Distributed COM Users', 'BUILTIN\Distributed COM Users',
            'Hyper-V Administrators', 'BUILTIN\Hyper-V Administrators',
            'Remote Management Users', 'BUILTIN\Remote Management Users'
        )

        # Always enumerate the full forest first. The full
        # parent/child map is what the sidebar tree uses: if we
        # restricted to scope domains too early, intermediate
        # parents (e.g. stago.grp when only cn.stago.grp is in
        # scope) would disappear and the tree would render
        # orphans flat. $aDomains stays as the SET FOR PROCESSING
        # (per-domain phase walk); $aDisplayDomains is the
        # SUPERSET FOR DISPLAY (scope + every ancestor of every
        # scope domain) which keeps the tree intact.
        $aAllDomains = @(Get-CurrentADForestDomains)
        Write-Host "Forest enumeration : $($aAllDomains.Count) domain(s)" -ForegroundColor Cyan
        $hFullDomainParent = @{}
        foreach ($oDom in $aAllDomains) {
            $hFullDomainParent[$oDom.Name] = if ($oDom.Parent) { $oDom.Parent.Name } else { "" }
        }

        # Multi-perim resolution. $hPerimData is ordered (insertion
        # order = tab order in the report). Each value carries the
        # identity tokens, the resolved AD objects, the DNS set of
        # in-scope domains, the upper-cased ancestor DN set used by
        # the per-domain Phase 2 to filter GPO Links to OUs touching
        # this perim, and the slug-cased tab id.
        $hPerimData = [ordered]@{}
        if ($bScoped) {
            Write-Progress -Activity $sCallerName -Status "Resolving perimeters..." -PercentComplete 5
            $hRA = @{}
            if ($Credential) { $hRA['Credential'] = $Credential }

            # Properties consumed by the perimeter inventory rendering
            # (Phase 1) + the disabled flag + the DN extraction below.
            # The custom Get-ADObject (PSSomeActiveDirectoryThings)
            # builds its result dictionary only from the explicitly
            # requested properties + objectclass: nothing is returned
            # by default, so distinguishedName has to be listed here
            # or the perim scope / ancestor walk below see empty DNs.
            $aInventoryProps = @('distinguishedName','samAccountName','displayName','mail','operatingSystem','userAccountControl')

            foreach ($sPerimName in $Perimeter.Keys) {
                $aIds = @($Perimeter[$sPerimName] | Where-Object { $_ })
                if ($aIds.Count -eq 0) { continue }

                $aObjects = @(Resolve-ADObject -Identity $aIds -Properties $aInventoryProps @hRA)

                $hScopeDom = @{}
                $hAncestors = @{}
                foreach ($oObj in $aObjects) {
                    # Bracket access (lowercase to match the LDAP
                    # attribute name keys the custom Get-ADObject
                    # stores in its result dictionary).
                    $sDn = [string]$oObj['distinguishedname']
                    if (-not $sDn) { continue }
                    $sDomDns = (($sDn -split ',') | ForEach-Object {
                        if ($_ -match '^DC=(.+)$') { $Matches[1] }
                    }) -join '.'
                    if ($sDomDns) { $hScopeDom[$sDomDns] = $true }

                    # Walk parents upward (every comma break splits an
                    # RDN off) and stamp every intermediate DN into
                    # the ancestor set - the GPO Links filter below
                    # is an "any link target in this set" test.
                    $sCur = $sDn
                    while ($sCur) {
                        $hAncestors[$sCur.ToUpperInvariant()] = $true
                        $i = $sCur.IndexOf(',')
                        if ($i -lt 0) { break }
                        $sCur = $sCur.Substring($i + 1)
                    }
                }

                $hPerimData[$sPerimName] = @{
                    Tab          = $sPerimName
                    Identities   = $aIds
                    Objects      = $aObjects
                    ScopeDomains = $hScopeDom
                    Ancestors    = $hAncestors
                }
                Write-Host ("Perimeter '$sPerimName' resolved : {0}/{1} objects across {2} domain(s)" -f `
                    $aObjects.Count, $aIds.Count, $hScopeDom.Count) -ForegroundColor Cyan
            }

            if ($hPerimData.Count -eq 0) {
                Write-Warning "$sCallerName : every perimeter produced 0 resolved objects; aborting."
                return
            }
        } else {
            # Unscoped: synthesise one default perim covering every
            # forest domain, no identity restriction, no GPO Links
            # filtering. Tab name stays "security" for back-compat.
            $hScopeDom = @{}
            foreach ($oDom in $aAllDomains) { $hScopeDom[$oDom.Name] = $true }
            $hPerimData['Security'] = @{
                Tab          = 'security'
                Identities   = @()
                Objects      = @()
                ScopeDomains = $hScopeDom
                Ancestors    = @{}
            }
        }

        # Union of every perim's in-scope domains. The Phase 2
        # per-domain loop walks this set so AD queries (Default PW
        # Policy, PSO, OU enumeration, GPO catalog, WMI) happen once
        # per domain regardless of how many perims share it. The
        # per-perim section emission downstream sees the same data,
        # filtered to each perim's Ancestors set where applicable.
        $hScopeDomainNames = @{}
        foreach ($oPerim in $hPerimData.Values) {
            foreach ($sDns in $oPerim.ScopeDomains.Keys) { $hScopeDomainNames[$sDns] = $true }
        }
        $aDomains = @($aAllDomains | Where-Object { $hScopeDomainNames.ContainsKey($_.Name) })
        if ($aDomains.Count -eq 0) {
            Write-Warning "$sCallerName : no in-scope domains; aborting."
            return
        }

        # Legacy aliases consumed by the existing Phase 2 code. They
        # now refer to the UNION across all perims; per-perim filtering
        # happens at the section-emission step. Existing inline filters
        # against $hPerimeterAncestors continue to work for the
        # unscoped path (Ancestors is empty so nothing is filtered out)
        # and for the single-perim case (where the union IS the perim).
        $hPerimeterAncestors = @{}
        foreach ($oPerim in $hPerimData.Values) {
            foreach ($sKey in $oPerim.Ancestors.Keys) { $hPerimeterAncestors[$sKey] = $true }
        }

        # Display set = scope + every ancestor of every scope
        # domain (so the sidebar tree keeps parents). In unscoped
        # mode this is just the full forest.
        $hDisplayDomains = @{}
        if ($bScoped) {
            foreach ($oDom in $aDomains) {
                $sCur = $oDom.Name
                while ($sCur) {
                    $hDisplayDomains[$sCur] = $true
                    $sNext = $hFullDomainParent[$sCur]
                    if (-not $sNext) { break }
                    $sCur = $sNext
                }
            }
        } else {
            foreach ($oDom in $aAllDomains) { $hDisplayDomains[$oDom.Name] = $true }
        }

        # Tag every item with notFilterable when we're in scoped
        # mode and the domain is *only* present as an ancestor
        # (i.e., it is in $hDisplayDomains but not in $aDomains).
        # New-HTMLReport reads that flag and renders the option
        # disabled (italic + greyed) so the auditor sees the
        # hierarchy without being misled into selecting a domain
        # that has no per-domain sections in this report.
        $hScopeOnlyDomains = @{}
        if ($bScoped) {
            foreach ($oDom in $aDomains) { $hScopeOnlyDomains[$oDom.Name] = $true }
        }

        function Get-DomainDepth {
            Param([string]$Name, [hashtable]$Parents)
            $d = 0; $s = $Name
            while ($Parents[$s]) { $d++; $s = $Parents[$s] }
            return $d
        }
        function Get-DomainHierarchicalOrder {
            Param([array]$Items, [string]$ParentName = '')
            $aResult = @()
            $aChildren = @($Items | Where-Object { $_.parent -eq $ParentName } | Sort-Object { $_.name })
            foreach ($oChild in $aChildren) {
                $aResult += [PSCustomObject]@{
                    name          = $oChild.name
                    depth         = $oChild.depth
                    parent        = $oChild.parent
                    notFilterable = $oChild.notFilterable
                }
                $aResult += Get-DomainHierarchicalOrder -Items $Items -ParentName $oChild.name
            }
            return $aResult
        }
        $aDomainsWithDepth = @($hDisplayDomains.Keys | ForEach-Object {
            $sParent = $hFullDomainParent[$_]
            if (-not $hDisplayDomains.ContainsKey($sParent)) { $sParent = '' }
            $bNotFilt = $bScoped -and (-not $hScopeOnlyDomains.ContainsKey($_))
            [PSCustomObject]@{
                name          = $_
                depth         = (Get-DomainDepth $_ $hFullDomainParent)
                parent        = $sParent
                notFilterable = $bNotFilt
            }
        })
        $aDomainContexts = @(Get-DomainHierarchicalOrder -Items $aDomainsWithDepth)

        # Per-perim domain contexts: each perimeter tab's sidebar
        # Domain filter shows only that perim's in-scope domains
        # (plus their ancestors as notFilterable rows for hierarchy
        # context). Without this, every perim tab would mirror the
        # forest-wide union list - the Filers tab would offer es.eu,
        # de.eu, au.stago, ... even though no filer lives there.
        foreach ($oPerim in $hPerimData.Values) {
            $hPerimDisplay = @{}
            foreach ($sDns in $oPerim.ScopeDomains.Keys) {
                $sCur = $sDns
                while ($sCur) {
                    $hPerimDisplay[$sCur] = $true
                    $sNext = $hFullDomainParent[$sCur]
                    if (-not $sNext) { break }
                    $sCur = $sNext
                }
            }
            $aPerimDepthList = @($hPerimDisplay.Keys | ForEach-Object {
                $sParent = $hFullDomainParent[$_]
                if (-not $hPerimDisplay.ContainsKey($sParent)) { $sParent = '' }
                [PSCustomObject]@{
                    name          = $_
                    depth         = (Get-DomainDepth $_ $hFullDomainParent)
                    parent        = $sParent
                    notFilterable = -not $oPerim.ScopeDomains.ContainsKey($_)
                }
            })
            $oPerim.DomainContexts = @(Get-DomainHierarchicalOrder -Items $aPerimDepthList)
        }

        # ===== SECURITY POLICIES (Password & Account Lockout) =====
        if ($IncludeSecurityPolicies) {
            # One tab per perimeter: each carries that perimeter's
            # Default Password Policy / PSO / OU Stats / GPO Links /
            # WMI Filters per domain. The unscoped pseudo-perim is
            # named "Security" with slug "security" so a single-tab
            # layout falls out naturally.
            foreach ($oPerim in $hPerimData.Values) {
                if ($oPerim.Tab -notin $aTabs) { $aTabs += $oPerim.Tab }
            }

            # Global tabs. Inventory groups one (perim, objectclass)
            # sub-section per perim so every perim's users / computers
            # stay column-typed. GPO Catalog hosts the cross-domain
            # deduplicated per-GPO panels and the cross-tab WSUS pivot.
            $sInventoryTab = "Inventory"
            if ($sInventoryTab -notin $aTabs) { $aTabs += $sInventoryTab }

            $sGPOTab = "GPO"
            if ($sGPOTab -notin $aTabs) { $aTabs += $sGPOTab }

            # Forest-wide map of unique GPO panels, keyed by
            # "<DisplayName>|<fingerprint>" so identical replicas across
            # domains collapse to one entry and divergent same-name GPOs
            # appear as separate entries. Each value is a hashtable with
            # DisplayName, SettingsData (the rows ready for rendering),
            # and Domains (the list of domain FQDNs where this variant
            # was seen). Emitted after the per-domain loop closes.
            $hForestGPOByKey = [ordered]@{}

            # Per-(domain, filter name) GPO usage counter for the WMI Filters
            # section. Filled while building $aGPOData of each domain; consumed
            # below when enriching the dedup'ed WMI filter rows.
            $hWMIUsage = @{}

            # Per-domain OU statistics. Indexed by $sDomainName; each value is
            # a hashtable of {OU DN -> stats row}. Consumed downstream by the
            # Dead-GPO detection's Empty-Target check, which looks up every
            # linked OU's enabled-principal count.
            $hOUStatsByDomain = @{}

            # Hardening catalog (registry / INI / audit subcategory lookups).
            # Loaded once and reused across every per-GPO scan below; the GPO
            # loop matches each registry.pol / GptTmpl.inf / audit.csv entry
            # against these tables to label hardening settings consistently
            # across the report.
            $oHardeningCatalog = Get-ADHardeningCatalog

            # Parent DN of a distinguished name (strips the leading RDN). The
            # split on the first comma is correct because RDN values that
            # legitimately contain commas are required by RFC 4514 to be
            # escaped ("\,"), so the first unescaped comma always separates
            # the leaf RDN from its parent.
            function Get-ParentDN {
                Param([string]$DN)
                if (-not $DN) { return '' }
                $i = $DN.IndexOf(',')
                if ($i -lt 0) { return '' }
                return $DN.Substring($i + 1)
            }

            # Human-readable container path. Drops the domain-DN suffix and
            # renders the remaining OU=... / CN=... segments root-first,
            # joined with " / ". Handles both OUs and non-OU containers
            # (CN=Users, CN=Computers, CN=Managed Service Accounts, ...);
            # CN= segments get a leading "(cn)" tag so they don't blend in
            # with real OUs visually. The domain root returns just the
            # domain FQDN.
            function Get-ContainerPath {
                Param([string]$DN, [string]$DomainDN, [string]$DomainName)
                if ($DN -eq $DomainDN) { return $DomainName }
                $sRelative = $DN
                if ($DN.EndsWith($DomainDN, [System.StringComparison]::OrdinalIgnoreCase)) {
                    $sRelative = $DN.Substring(0, $DN.Length - $DomainDN.Length).TrimEnd(',')
                }
                $aParts = $sRelative -split '(?<!\\),'
                $aSegments = @(
                    $aParts | Where-Object { $_ -match '^(OU|CN)=' } | ForEach-Object {
                        if ($_ -match '^OU=(.+)$') { $Matches[1] }
                        elseif ($_ -match '^CN=(.+)$') { "(cn) $($Matches[1])" }
                    }
                )
                [array]::Reverse($aSegments)
                return "$DomainName / $($aSegments -join ' / ')"
            }

            # ===== PERIMETER INVENTORY (scoped mode only) =====
            # Global Inventory tab carries one section per (perim,
            # objectclass) pair. Splitting per objectclass keeps the
            # column sets clean (users get mail, computers get
            # operatingSystem); prefixing the title with the perim
            # name lets the auditor scan vertically through
            # "Biomedical / Users", "Biomedical / Computers",
            # "Filers / Computers" without confusion. Class ordering
            # is stable (user, computer, then whatever else exists
            # alphabetically) so two perims hosting both classes
            # display them in the same order.
            if ($bScoped) {
                $iTotalInvObjects = 0
                $iTotalInvClasses = 0
                foreach ($sPerimName in $hPerimData.Keys) {
                    $oPerim = $hPerimData[$sPerimName]
                    if ($oPerim.Objects.Count -eq 0) { continue }

                    $hByClass = @{}
                    foreach ($oObj in $oPerim.Objects) {
                        $sClass = [string]$oObj['objectclass']
                        if (-not $sClass) { $sClass = 'unknown' }
                        if (-not $hByClass.ContainsKey($sClass)) { $hByClass[$sClass] = @() }
                        $hByClass[$sClass] += $oObj
                    }

                    # Stable ordering: user, computer, then alpha.
                    $aClassOrder = @('user','computer') + @($hByClass.Keys | Where-Object { $_ -notin 'user','computer' } | Sort-Object)
                    foreach ($sClass in $aClassOrder) {
                        if (-not $hByClass.ContainsKey($sClass)) { continue }
                        $aRows = @($hByClass[$sClass] | ForEach-Object {
                            $sDn        = [string]$_['distinguishedname']
                            $sDomainDN  = (($sDn -split ',') | Where-Object { $_ -match '^DC=' }) -join ','
                            $sDomainDns = (($sDomainDN -split ',') | ForEach-Object {
                                if ($_ -match '^DC=(.+)$') { $Matches[1] }
                            }) -join '.'
                            $bDisabled = $false
                            if ($null -ne $_['userAccountControl']) {
                                $bDisabled = (([int]$_['userAccountControl']) -band 2) -ne 0
                            }
                            $oOrdered = [ordered]@{
                                name        = [string]$_['samaccountname']
                                displayName = [string]$_['displayName']
                            }
                            switch ($sClass) {
                                'user'     { $oOrdered['mail']            = [string]$_['mail'] }
                                'computer' { $oOrdered['operatingSystem'] = [string]$_['operatingsystem'] }
                            }
                            $oOrdered['domain']            = $sDomainDns
                            $oOrdered['ouPath']            = Get-ContainerPath -DN (Get-ParentDN $sDn) -DomainDN $sDomainDN -DomainName $sDomainDns
                            $oOrdered['distinguishedName'] = $sDn
                            $oOrdered['disabled']          = $bDisabled
                            [PSCustomObject]$oOrdered
                        } | Sort-Object name)

                        $sTitle = "$sPerimName / $sClass ($($aRows.Count))"
                        $sId = "sec_$iTocIndex"; $iTocIndex++
                        $aSectionFiles += ConvertTo-HTMLSectionV2 -Title $sTitle -Id $sId `
                            -Data $aRows -Tab $sInventoryTab `
                            -NameProperty 'name' -DetectAllColumns -LinkableColumns 'name'
                        $iTotal += $aRows.Count
                        $iTotalInvObjects += $aRows.Count
                        $iTotalInvClasses++
                    }
                }
                if ($iTotalInvObjects -gt 0) {
                    Write-Host "Perimeter inventory : $iTotalInvObjects object(s) across $iTotalInvClasses (perim, class) section(s)" -ForegroundColor Cyan
                }
            }

            $iDomainCount = $aDomains.Count
            $iDomainIdx = 0
            foreach ($oDomain in $aDomains) {
                $iDomainIdx++
                $sDomainName = $oDomain.Name

                # Perimeters that cover this domain. Each section
                # emitted below iterates this list so the same data
                # lands once per perim tab where the domain is in
                # scope. Order is the insertion order of $hPerimData,
                # which matches the tab order in the report.
                $aPerimsForDomain = @($hPerimData.Values | Where-Object { $_.ScopeDomains.ContainsKey($sDomainName) })

                # Build per-domain AD params (override Server with domain name)
                $hDomainParams = @{ Server = $sDomainName }
                if ($Credential) { $hDomainParams['Credential'] = $Credential }

                # Open a PSSession to the domain so every SYSVOL read in this
                # iteration runs under the remote DC's identity. Failure here
                # is non-fatal: we log a warning and fall back to local reads
                # (the rest of the domain's data - LDAP queries - still works).
                $oRemoteSession = $null
                if ($PSRemoting) {
                    $hSessionParams = @{
                        ComputerName  = $sDomainName
                        ErrorAction   = 'Stop'
                    }
                    if ($Credential) { $hSessionParams['Credential'] = $Credential }
                    try {
                        $oRemoteSession = New-PSSession @hSessionParams
                    } catch {
                        Write-Warning "$sCallerName : $sDomainName / cannot open PSSession - $_"
                    }
                }
                # Threaded into every GPO helper that reads SYSVOL files.
                $hGPOParams = @{}
                if ($oRemoteSession) { $hGPOParams['Session'] = $oRemoteSession }

                # --- Default Domain Password & Lockout Policy ---
                Write-Progress -Activity $sCallerName -Status "$sDomainName - Default Password Policy..." `
                    -PercentComplete (Get-DomainStepProgress -Idx $iDomainIdx -Count $iDomainCount -Start 20 -End 65 -Step 0.00)

                try {
                    $oDefaultPolicy = Get-ADDefaultDomainPasswordPolicy @hDomainParams -ErrorAction Stop

                    $aDefaultPolicyData = @(
                        [PSCustomObject][ordered]@{
                            setting = "Minimum Password Length"
                            value   = "$($oDefaultPolicy.MinPasswordLength) characters"
                            cmmc    = Get-CMMCControl 'Minimum Password Length'
                        },
                        [PSCustomObject][ordered]@{
                            setting = "Password Complexity Enabled"
                            value   = "$($oDefaultPolicy.ComplexityEnabled)"
                            cmmc    = Get-CMMCControl 'Password Complexity Enabled'
                        },
                        [PSCustomObject][ordered]@{
                            setting = "Password History Count"
                            value   = "$($oDefaultPolicy.PasswordHistoryCount) passwords remembered"
                            cmmc    = Get-CMMCControl 'Password History Count'
                        },
                        [PSCustomObject][ordered]@{
                            setting = "Maximum Password Age"
                            value   = if ($oDefaultPolicy.MaxPasswordAge -eq [TimeSpan]::Zero) { "Never expires" } else { "$($oDefaultPolicy.MaxPasswordAge.Days) days" }
                            cmmc    = Get-CMMCControl 'Maximum Password Age'
                        },
                        [PSCustomObject][ordered]@{
                            setting = "Minimum Password Age"
                            value   = "$($oDefaultPolicy.MinPasswordAge.Days) days"
                            cmmc    = Get-CMMCControl 'Minimum Password Age'
                        },
                        [PSCustomObject][ordered]@{
                            setting = "Reversible Encryption Enabled"
                            value   = "$($oDefaultPolicy.ReversibleEncryptionEnabled)"
                            cmmc    = Get-CMMCControl 'Reversible Encryption Enabled'
                        },
                        [PSCustomObject][ordered]@{
                            setting = "Account Lockout Threshold"
                            value   = if ($oDefaultPolicy.LockoutThreshold -eq 0) { "Disabled (no lockout)" } else { "$($oDefaultPolicy.LockoutThreshold) invalid attempts" }
                            cmmc    = Get-CMMCControl 'Account Lockout Threshold'
                        },
                        [PSCustomObject][ordered]@{
                            setting = "Account Lockout Duration"
                            value   = if ($oDefaultPolicy.LockoutDuration -eq [TimeSpan]::Zero) { "Until admin unlock" } else { "$($oDefaultPolicy.LockoutDuration.TotalMinutes) minutes" }
                            cmmc    = Get-CMMCControl 'Account Lockout Duration'
                        },
                        [PSCustomObject][ordered]@{
                            setting = "Lockout Observation Window"
                            value   = "$($oDefaultPolicy.LockoutObservationWindow.TotalMinutes) minutes"
                            cmmc    = Get-CMMCControl 'Lockout Observation Window'
                        }
                    )

                    # Default PW Policy is domain-wide - same payload
                    # for every perim that has at least one object in
                    # this domain. Each perim tab gets its own copy so
                    # the auditor sees the policy without leaving the
                    # perim view.
                    foreach ($oPerim in $aPerimsForDomain) {
                        $sId = "sec_$iTocIndex"; $iTocIndex++
                        $aSectionFiles += ConvertTo-HTMLSectionV2 -Title "Default Password & Lockout Policy" -Id $sId `
                            -Data $aDefaultPolicyData -Tab $oPerim.Tab -Context $sDomainName `
                            -NameProperty 'setting' -DetectAllColumns
                        $iTotal += $aDefaultPolicyData.Count
                    }
                    Write-Host "$sDomainName : Default Password Policy collected" -ForegroundColor Cyan
                } catch {
                    Write-Warning "$sCallerName : $sDomainName / Default Password Policy - $_"
                }

                # --- Fine-Grained Password Policies (PSOs) ---
                Write-Progress -Activity $sCallerName -Status "$sDomainName - Fine-Grained Password Policies..." `
                    -PercentComplete (Get-DomainStepProgress -Idx $iDomainIdx -Count $iDomainCount -Start 20 -End 65 -Step 0.05)

                try {
                    $aPSOs = @(Get-ADFineGrainedPasswordPolicy @hDomainParams -ErrorAction Stop)

                    if ($aPSOs.Count -gt 0) {
                        $aPSOSummary = @($aPSOs | Sort-Object Precedence | ForEach-Object {
                            $sAppliesTo = ($_.AppliesTo | ForEach-Object {
                                try { (Get-ADObject $_ @hDomainParams -Properties name).name } catch { $_ }
                            }) -join ", "

                            [PSCustomObject][ordered]@{
                                name                        = $_.Name
                                precedence                  = $_.Precedence
                                minPasswordLength           = $_.MinPasswordLength
                                complexityEnabled           = $_.ComplexityEnabled
                                passwordHistoryCount        = $_.PasswordHistoryCount
                                maxPasswordAge              = if ($_.MaxPasswordAge -eq [TimeSpan]::Zero) { "Never" } else { "$($_.MaxPasswordAge.Days)d" }
                                minPasswordAge              = "$($_.MinPasswordAge.Days)d"
                                lockoutThreshold            = if ($_.LockoutThreshold -eq 0) { "Disabled" } else { $_.LockoutThreshold }
                                lockoutDuration             = if ($_.LockoutDuration -eq [TimeSpan]::Zero) { "Until unlock" } else { "$($_.LockoutDuration.TotalMinutes)min" }
                                lockoutObservationWindow    = "$($_.LockoutObservationWindow.TotalMinutes)min"
                                reversibleEncryptionEnabled = $_.ReversibleEncryptionEnabled
                                appliesTo                   = $sAppliesTo
                            }
                        })

                        foreach ($oPerim in $aPerimsForDomain) {
                            $sId = "sec_$iTocIndex"; $iTocIndex++
                            $aSectionFiles += ConvertTo-HTMLSectionV2 -Title "Fine-Grained Password Policies (PSOs)" -Id $sId `
                                -Data $aPSOSummary -Tab $oPerim.Tab -Context $sDomainName `
                                -NameProperty 'name' -DetectAllColumns
                            $iTotal += $aPSOSummary.Count
                        }
                        Write-Host "$sDomainName : $($aPSOs.Count) Fine-Grained Password Policy(ies) found" -ForegroundColor Cyan
                    } else {
                        Write-Verbose "$sCallerName : $sDomainName : No Fine-Grained Password Policies defined"
                    }
                } catch {
                    Write-Warning "$sCallerName : $sDomainName / Fine-Grained Password Policies - $_"
                }

                # --- OU Statistics ---------------------------------------
                # Enumerate every OU + the domain root, then count users and
                # computers (direct/recursive, with disabled counterparts).
                # Recursive counters use a walk-up: each principal's parent
                # OU and every ancestor up to the domain root are incremented.
                # The resulting per-OU table doubles as the input source for
                # the Dead-GPO Empty-Target check below: total_enabled_recursive
                # is 0 when an OU (and everything beneath it) holds no enabled
                # account, so a GPO linked only to such OUs has no audience.
                #
                # Skipped in scoped mode: the per-perim Inventory tab
                # already surfaces every in-scope user / computer with
                # its ouPath column, so the per-domain OU stats become
                # redundant noise. Dead-GPO Empty-Target degrades
                # gracefully (downstream check falls back to an empty
                # $hOUStatsForDomain lookup).
                if (-not $bScoped) {
                Write-Progress -Activity $sCallerName -Status "$sDomainName - OU Statistics..." `
                    -PercentComplete (Get-DomainStepProgress -Idx $iDomainIdx -Count $iDomainCount -Start 20 -End 65 -Step 0.15)

                try {
                    # Convert FQDN to DN; e.g., "grp.stago.au" → "DC=grp,DC=stago,DC=au".
                    # AD always returns DNs in this form, so direct string comparison
                    # against $oOU.DistinguishedName values is safe.
                    $sDomainDN = "DC=" + ($sDomainName -replace '\.', ',DC=')

                    # No -SearchBase here: Get-ADObject already binds to
                    # LDAP://<Server>/<defaultNamingContext> via -Server, and
                    # passing -SearchBase overwrites SearchRoot with a
                    # serverless LDAP:// path (binding to the wrong directory,
                    # which is why only the seeded domain root was returned).
                    # Subtree is the DirectorySearcher default.
                    # We fetch OUs PLUS the AD containers that can hold user
                    # or computer principals (CN=Users, CN=Computers, CN=Managed
                    # Service Accounts, CN=ForeignSecurityPrincipals, ...). They
                    # are seeded the same way as OUs so the walk-up below credits
                    # them with their direct counts instead of letting their
                    # population only roll up to the domain root row.
                    #   organizationalUnit : every OU
                    #   container          : well-known + custom CN= holders
                    #   builtinDomain      : CN=Builtin (groups only in practice,
                    #                        kept for completeness)
                    $aOUs = @(Get-ADObject @hDomainParams `
                        -LDAPFilter '(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=builtinDomain))' `
                        -Properties 'distinguishedName' -ResultPageSize 1000)

                    $hOUStats = [ordered]@{}
                    # Seed domain root so users/computers living directly under
                    # the domain (CN=Users, CN=Computers default containers) are
                    # counted somewhere. Without this row a GPO linked to the
                    # domain root would always look Empty-Target.
                    $hOUStats[$sDomainDN] = [PSCustomObject][ordered]@{
                        ou_dn                        = $sDomainDN
                        ou_path                      = $sDomainName
                        users_direct                 = 0
                        users_disabled_direct        = 0
                        users_recursive              = 0
                        users_disabled_recursive     = 0
                        computers_direct             = 0
                        computers_disabled_direct    = 0
                        computers_recursive          = 0
                        computers_disabled_recursive = 0
                        sub_ou_count                 = 0
                    }
                    foreach ($oOU in $aOUs) {
                        $sDN = $oOU.distinguishedname
                        if (-not $sDN) { continue }
                        $hOUStats[$sDN] = [PSCustomObject][ordered]@{
                            ou_dn                        = $sDN
                            ou_path                      = Get-ContainerPath -DN $sDN -DomainDN $sDomainDN -DomainName $sDomainName
                            users_direct                 = 0
                            users_disabled_direct        = 0
                            users_recursive              = 0
                            users_disabled_recursive     = 0
                            computers_direct             = 0
                            computers_disabled_direct    = 0
                            computers_recursive          = 0
                            computers_disabled_recursive = 0
                            sub_ou_count                 = 0
                        }
                    }

                    # Direct child OU count (one level only).
                    foreach ($oOU in $aOUs) {
                        $sParent = Get-ParentDN $oOU.distinguishedname
                        if ($hOUStats.Contains($sParent)) {
                            $hOUStats[$sParent].sub_ou_count++
                        }
                    }

                    # --- Walk-up helper (closure over $hOUStats / $sDomainDN) ---
                    # Increments the named counter on the principal's parent OU
                    # (direct) and on every ancestor up to and including the
                    # domain root (recursive). Containers (CN=Users) and other
                    # non-OU parents aren't in $hOUStats and are simply skipped
                    # for the direct counter — recursive still fires once the
                    # walk reaches an ancestor OU or the domain root.
                    $sbCount = {
                        Param([string]$ParentDN, [bool]$Disabled, [string]$Direct, [string]$DirectDisabled, [string]$Recursive, [string]$RecursiveDisabled)
                        if ($hOUStats.Contains($ParentDN)) {
                            $hOUStats[$ParentDN].$Direct++
                            if ($Disabled) { $hOUStats[$ParentDN].$DirectDisabled++ }
                        }
                        $sCurrent = $ParentDN
                        while ($sCurrent) {
                            if ($hOUStats.Contains($sCurrent)) {
                                $hOUStats[$sCurrent].$Recursive++
                                if ($Disabled) { $hOUStats[$sCurrent].$RecursiveDisabled++ }
                            }
                            if ($sCurrent -eq $sDomainDN) { break }
                            $sCurrent = Get-ParentDN $sCurrent
                        }
                    }

                    # Users (same -SearchBase caveat as the OU query above).
                    $aUsers = @(Get-ADObject @hDomainParams -User `
                        -Properties 'distinguishedName', 'userAccountControl' -ResultPageSize 1000)
                    foreach ($oU in $aUsers) {
                        $bDisabled = $false
                        if ($null -ne $oU.userAccountControl) {
                            $bDisabled = ([int]$oU.userAccountControl -band 2) -ne 0
                        }
                        & $sbCount (Get-ParentDN $oU.distinguishedname) $bDisabled `
                            'users_direct' 'users_disabled_direct' 'users_recursive' 'users_disabled_recursive'
                    }

                    # Computers (same -SearchBase caveat as the OU query above).
                    $aComputers = @(Get-ADObject @hDomainParams -Computer `
                        -Properties 'distinguishedName', 'userAccountControl' -ResultPageSize 1000)
                    foreach ($oC in $aComputers) {
                        $bDisabled = $false
                        if ($null -ne $oC.userAccountControl) {
                            $bDisabled = ([int]$oC.userAccountControl -band 2) -ne 0
                        }
                        & $sbCount (Get-ParentDN $oC.distinguishedname) $bDisabled `
                            'computers_direct' 'computers_disabled_direct' 'computers_recursive' 'computers_disabled_recursive'
                    }

                    # Stash for the Dead-GPO Empty-Target check, then build the
                    # output rows (totals computed last so they stay consistent
                    # if a downstream tweak changes the underlying counts).
                    $hOUStatsByDomain[$sDomainName] = $hOUStats

                    $aOUSummary = @($hOUStats.Values | ForEach-Object {
                        $iTotalRec   = $_.users_recursive + $_.computers_recursive
                        $iEnabledRec = ($_.users_recursive - $_.users_disabled_recursive) +
                                       ($_.computers_recursive - $_.computers_disabled_recursive)
                        [PSCustomObject][ordered]@{
                            ou_path                      = $_.ou_path
                            ou_dn                        = $_.ou_dn
                            users_direct                 = $_.users_direct
                            users_disabled_direct        = $_.users_disabled_direct
                            users_recursive              = $_.users_recursive
                            users_disabled_recursive     = $_.users_disabled_recursive
                            computers_direct             = $_.computers_direct
                            computers_disabled_direct    = $_.computers_disabled_direct
                            computers_recursive          = $_.computers_recursive
                            computers_disabled_recursive = $_.computers_disabled_recursive
                            sub_ou_count                 = $_.sub_ou_count
                            total_recursive              = $iTotalRec
                            total_enabled_recursive      = $iEnabledRec
                        }
                    } | Sort-Object ou_path)

                    if ($aOUSummary.Count -gt 0) {
                        $sId = "sec_$iTocIndex"; $iTocIndex++
                        # ou_dn is the cross-nav anchor (matched against linkedTo
                        # on the GPO Links table) and is hidden from the rendered
                        # grid; ou_path carries the human-readable label.
                        # total_enabled_recursive == 0 → row grayed out (the
                        # DisabledFlagProperty check treats 0 as "disabled"),
                        # surfacing OU branches with no enabled audience.
                        $aSectionFiles += ConvertTo-HTMLSectionV2 -Title "OU Statistics" -Id $sId `
                            -Data $aOUSummary -Tab $sInventoryTab -Context $sDomainName `
                            -NameProperty 'ou_dn' -NoSort -DetectAllColumns `
                            -DisabledFlagProperty 'total_enabled_recursive' `
                            -HiddenCols @('ou_dn') `
                            -RowFilters @(
                                @{ Label = 'Hide OUs with no enabled accounts (recursive)'; HideFlag = 'd'; Default = $true }
                            )
                        $iTotal += $aOUSummary.Count
                        Write-Host "$sDomainName : $($aOUSummary.Count) OU statistic row(s) collected" -ForegroundColor Cyan
                    }
                } catch {
                    Write-Warning "$sCallerName : $sDomainName / OU Statistics - $_"
                }
                } # end if (-not $bScoped) wrapping OU Statistics

                # --- GPO Links & Security Settings ---
                Write-Progress -Activity $sCallerName -Status "$sDomainName - GPO Links & Security Settings..." `
                    -PercentComplete (Get-DomainStepProgress -Idx $iDomainIdx -Count $iDomainCount -Start 20 -End 65 -Step 0.40)

                # Cleared per-iteration so a previous domain's data can't leak
                # into Dead-GPO detection if Get-ADGroupPolicyLinkSecuritySettings
                # throws before reassigning.
                $aGPOData = @()
                try {
                    # Perimeter upstream filter: in scoped mode, derive
                    # the subset of $hPerimeterAncestors that live in
                    # the current domain and feed it as -FilterTargets
                    # so Get-ADGroupPolicyLinkSecuritySettings drops
                    # out-of-scope OUs before the expensive per-GPO
                    # fetch + GptTmpl.inf parse. The downstream
                    # $aUniqueGPOs / $hForestGPOByKey dedup automatically
                    # narrows to the perimeter GPO Catalog too.
                    $hLinkParams = @{}
                    if ($bScoped -and $hPerimeterAncestors.Count -gt 0) {
                        $sDomainDNUpper = ("DC=" + ($sDomainName -replace '\.', ',DC=')).ToUpperInvariant()
                        $aDomainPerimeterOUs = @($hPerimeterAncestors.Keys | Where-Object {
                            ([string]$_).EndsWith($sDomainDNUpper)
                        })
                        if ($aDomainPerimeterOUs.Count -gt 0) {
                            $hLinkParams['FilterTargets'] = $aDomainPerimeterOUs
                        }
                    }

                    $aGPOData = @(Get-ADGroupPolicyLinkSecuritySettings -Recursive @hDomainParams @hGPOParams @hLinkParams)

                    if ($bScoped) {
                        Write-Host "$sDomainName : GPO Links (perimeter scope) = $($aGPOData.Count) row(s)" -ForegroundColor Cyan
                    }

                    if ($aGPOData.Count -gt 0) {
                        # Per-GPO FilteredSettings is populated by:
                        #   - Restricted Groups + GPP Local Users and Groups
                        #     (privileged local membership)
                        #   - LAPS settings (legacy + Windows LAPS)
                        #   - Hardening catalog match (GptTmpl entries
                        #     including Privilege Rights, BOTH registry.pol
                        #     hives, audit.csv subcategories, GPP scheduled
                        #     tasks, network profiles)
                        # The legacy hand-curated lockout / inactivity
                        # filter was removed in 1.6.1; those settings are
                        # now covered by the catalog (lockout keys via
                        # the INI catalog 'system access|*' entries,
                        # inactivity via the Registry catalog
                        # 'software\microsoft\...\inactivitytimeoutsecs'
                        # entry) and surface with friendly category
                        # labels ('Auth') instead of bare GptTmpl
                        # section names ('System Access' / 'Registry
                        # Values').
                        foreach ($oGPO in $aGPOData) {
                            $aFiltered = @()

                            # --- Local privileged group memberships -----------
                            # Restricted Groups + GPP Local Users and Groups.
                            # The module function returns ALL local groups; we
                            # filter here to administrator-equivalent ones so
                            # the Security tab keeps its CMMC-3.1.5 focus.
                            if ($oGPO.GPCFileSysPath) {
                                try {
                                    $hLGParams = @{ GPCFileSysPath = $oGPO.GPCFileSysPath }
                                    if ($Credential) { $hLGParams['Credential'] = $Credential }
                                    $aLocalGroups = @(Get-ADGroupPolicyLocalGroupMembership @hLGParams @hGPOParams)

                                    foreach ($oLG in $aLocalGroups) {
                                        $bInScope = $false
                                        if ($oLG.GroupSid -and ($aPrivilegedLocalGroupSids -contains $oLG.GroupSid)) {
                                            $bInScope = $true
                                        } elseif ($oLG.ResolvedName -and ($aPrivilegedLocalGroupNames -contains $oLG.ResolvedName)) {
                                            $bInScope = $true
                                        } elseif ($oLG.GroupName -and ($aPrivilegedLocalGroupNames -contains $oLG.GroupName)) {
                                            $bInScope = $true
                                        }
                                        if (-not $bInScope) { continue }

                                        $sSection = if ($oLG.Source -eq 'GPP') {
                                            'GPP - Local Group Membership'
                                        } else {
                                            'Restricted Groups'
                                        }

                                        $sLabel = if ($oLG.GroupSid) {
                                            "$($oLG.GroupName) ($($oLG.GroupSid))"
                                        } else {
                                            $oLG.GroupName
                                        }
                                        $sSetting = if ($oLG.Action) {
                                            "$sLabel [$($oLG.Action)]"
                                        } else {
                                            $sLabel
                                        }

                                        # Compact value: members with +/- prefix,
                                        # then parent groups (__Memberof) and
                                        # GPP flags.
                                        $aValueParts = @()
                                        if ($oLG.Members.Count -gt 0) {
                                            $aMemberStrs = @($oLG.Members | ForEach-Object {
                                                $sPrefix = switch ($_.Action) {
                                                    'Add'    { '+ ' }
                                                    'Remove' { '- ' }
                                                    'Set'    { '= ' }
                                                    default  { '' }
                                                }
                                                "$sPrefix$($_.Name)"
                                            })
                                            $aValueParts += ($aMemberStrs -join ', ')
                                        } elseif ($oLG.Action -eq 'ReplaceMembers') {
                                            $aValueParts += '(no members)'
                                        }
                                        if ($oLG.ParentGroups.Count -gt 0) {
                                            $aValueParts += 'MemberOf: ' + (@($oLG.ParentGroups | ForEach-Object { $_.Name }) -join ', ')
                                        }
                                        if ($oLG.DeleteAllUsers)  { $aValueParts += 'deleteAllUsers=true' }
                                        if ($oLG.DeleteAllGroups) { $aValueParts += 'deleteAllGroups=true' }
                                        if ($oLG.NewName)         { $aValueParts += "newName=$($oLG.NewName)" }

                                        $aFiltered += [PSCustomObject][ordered]@{
                                            Section = $sSection
                                            Setting = $sSetting
                                            Type    = $oLG.Source
                                            Value   = ($aValueParts -join '; ')
                                        }
                                    }
                                } catch {
                                    Write-Warning "$sCallerName : $($oGPO.DisplayName) / Local groups - $_"
                                }
                            }

                            # --- LAPS GPO settings ---------------------------
                            # Legacy LAPS + Windows LAPS. The module function
                            # parses Machine\registry.pol and returns one row
                            # per LAPS-related registry value with a
                            # human-readable DisplayValue.
                            if ($oGPO.GPCFileSysPath) {
                                try {
                                    $hLAPSParams = @{ GPCFileSysPath = $oGPO.GPCFileSysPath }
                                    if ($Credential) { $hLAPSParams['Credential'] = $Credential }
                                    $aLAPS = @(Get-ADGroupPolicyLAPSSettings @hLAPSParams @hGPOParams)
                                    foreach ($oL in $aLAPS) {
                                        $aFiltered += [PSCustomObject][ordered]@{
                                            Section = "LAPS Policy - $($oL.Source)"
                                            Setting = $oL.Value
                                            Type    = $oL.Type
                                            Value   = $oL.DisplayValue
                                        }
                                    }
                                } catch {
                                    Write-Warning "$sCallerName : $($oGPO.DisplayName) / LAPS - $_"
                                }
                            }

                            # --- Hardening catalog match ---------------------
                            # Three sources feed the catalog: GptTmpl.inf
                            # entries (both [Registry Values] and INI-style
                            # sections), Machine\registry.pol, and audit.csv
                            # subcategories. A small (section|setting) dedup
                            # set prevents the legacy lockout / inactivity /
                            # screen-saver rows from being duplicated when
                            # the catalog also recognises them - the legacy
                            # rows win and keep their original labels.
                            $hSeen = @{}
                            foreach ($oRow in $aFiltered) {
                                $hSeen["$($oRow.Section.ToLower())|$($oRow.Setting.ToLower())"] = $true
                            }

                            # 1. GptTmpl.inf - Registry Values, INI sections,
                            #    and [Privilege Rights] (User Rights
                            #    Assignment). For Privilege Rights, the
                            #    Value column is a comma-separated list of
                            #    "*SID" tokens (and occasionally raw
                            #    Domain\Name strings); each "*SID" is
                            #    resolved via Resolve-ADSidName so the
                            #    table shows both the raw SID and the
                            #    friendly NT-account form side-by-side.
                            foreach ($oSec in $oGPO.SecuritySettings) {
                                if (-not $oSec.Section -or -not $oSec.Setting) { continue }
                                $hHit = $null
                                $sNorm = $null
                                if ($oSec.Section -eq 'Registry Values') {
                                    $sNorm = ($oSec.Setting -replace '^(MACHINE|USER)\\', '').ToLower()
                                    $hHit  = $oHardeningCatalog.Registry[$sNorm]
                                } else {
                                    $sNorm = "$($oSec.Section)|$($oSec.Setting)".ToLower()
                                    $hHit  = $oHardeningCatalog.INI[$sNorm]
                                }
                                if (-not $hHit) { continue }
                                # Skip if the legacy filter already emitted this
                                # row under its own friendlier label.
                                if ($hSeen.ContainsKey("$($oSec.Section.ToLower())|$($oSec.Setting.ToLower())")) { continue }

                                $sValue = "$($oSec.Value)"
                                if ($oSec.Section -eq 'Privilege Rights' -and $sValue) {
                                    # Each token is either "*<SID>" or a
                                    # raw NT-account string; SID tokens get
                                    # dual-display, non-SID tokens pass
                                    # through unchanged.
                                    $aTokens = @(($sValue -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                                    $aRendered = @()
                                    foreach ($sTok in $aTokens) {
                                        if ($sTok -match '^\*(?<sid>S-1-[\d-]+)$') {
                                            $sSid  = $Matches['sid']
                                            $sName = Resolve-ADSidName -Sid $sSid
                                            if ($sName) { $aRendered += "*$sSid ($sName)" } else { $aRendered += "*$sSid" }
                                        } else {
                                            $aRendered += $sTok
                                        }
                                    }
                                    $sValue = ($aRendered -join ', ')
                                }

                                $aFiltered += [PSCustomObject][ordered]@{
                                    Section = $hHit.Category
                                    Setting = "$($hHit.Name) [$($oSec.Setting)]"
                                    Type    = $oSec.Type
                                    Value   = $sValue
                                    _CMMC   = $hHit.CMMC
                                }
                            }

                            # 2. registry.pol - full scan of BOTH hives
                            #    (Machine + User) against the catalog.
                            #    The hive prefix is tagged in the Setting
                            #    label ([HKLM\...!Value] / [HKCU\...!Value])
                            #    so an auditor can tell which side a
                            #    particular setting comes from.
                            if ($oGPO.GPCFileSysPath) {
                                $aPolFiles = @(
                                    @{ Path = 'Machine\registry.pol'; Hive = 'HKLM' }
                                    @{ Path = 'User\registry.pol';    Hive = 'HKCU' }
                                )
                                foreach ($hPol in $aPolFiles) {
                                    $sPolPath = Join-Path $oGPO.GPCFileSysPath $hPol.Path
                                    try {
                                        $aEntries = @(Get-ADGroupPolicyRegistryPolicy -Path $sPolPath @hGPOParams)
                                        foreach ($oEntry in $aEntries) {
                                            $sNorm = "$($oEntry.Key)\$($oEntry.Value)".ToLower()
                                            $hHit  = $oHardeningCatalog.Registry[$sNorm]
                                            if (-not $hHit) { continue }

                                            $sDisplay = if ($oEntry.Data -is [array]) {
                                                ($oEntry.Data -join ', ')
                                            } elseif ($oEntry.Type -eq 'REG_BINARY' -and $oEntry.Data -is [byte[]]) {
                                                # Binary blobs (NetCease SDDL, etc.) - show length, not bytes.
                                                "($($oEntry.Data.Length) bytes)"
                                            } else {
                                                "$($oEntry.Data)"
                                            }

                                            $aFiltered += [PSCustomObject][ordered]@{
                                                Section = $hHit.Category
                                                Setting = "$($hHit.Name) [$($hPol.Hive)\$($oEntry.Key)!$($oEntry.Value)]"
                                                Type    = $oEntry.Type
                                                Value   = $sDisplay
                                                _CMMC   = $hHit.CMMC
                                            }
                                        }
                                    } catch {
                                        Write-Warning "$sCallerName : $($oGPO.DisplayName) / $($hPol.Path) - $_"
                                    }
                                }
                            }

                            # 3. audit.csv - Advanced Audit Configuration.
                            # CSV columns: Machine,Policy Target,Subcategory,
                            # Subcategory GUID,Inclusion,Exclusion,Setting Value.
                            # Match on the GUID (stable across OS versions); the
                            # Setting Value column maps to 0/1/2/3 = none/
                            # success/failure/both.
                            if ($oGPO.GPCFileSysPath) {
                                $sAuditCsv = Join-Path $oGPO.GPCFileSysPath 'Machine\Microsoft\Windows NT\Audit\audit.csv'
                                $hAuditReadParams = @{ Path = $sAuditCsv; Mode = 'Text' }
                                if ($oRemoteSession) { $hAuditReadParams['Session'] = $oRemoteSession }
                                try {
                                    $aAuditLines = Read-ADPolicyFile @hAuditReadParams
                                    if ($aAuditLines -and $aAuditLines.Count -gt 1) {
                                        foreach ($sLine in ($aAuditLines | Select-Object -Skip 1)) {
                                            if (-not $sLine -or -not $sLine.Trim()) { continue }
                                            $aParts = $sLine -split ','
                                            if ($aParts.Count -lt 7) { continue }
                                            $sGUID = $aParts[3].Trim()
                                            $hHit  = $oHardeningCatalog.AuditSub[$sGUID]
                                            if (-not $hHit) { continue }
                                            $iVal = 0
                                            [void][int]::TryParse($aParts[6].Trim(), [ref]$iVal)
                                            $sVal = switch ($iVal) {
                                                0 { 'No Auditing' }
                                                1 { 'Success' }
                                                2 { 'Failure' }
                                                3 { 'Success, Failure' }
                                                default { "Value=$iVal" }
                                            }
                                            $aFiltered += [PSCustomObject][ordered]@{
                                                Section = $hHit.Category
                                                Setting = "$($hHit.Name) [$sGUID]"
                                                Type    = 'Audit Subcategory'
                                                Value   = $sVal
                                                _CMMC   = $hHit.CMMC
                                            }
                                        }
                                    }
                                } catch {
                                    Write-Warning "$sCallerName : $($oGPO.DisplayName) / audit.csv - $_"
                                }
                            }

                            # 4. ScheduledTasks.xml - GPP scheduled tasks
                            #    deployed by the GPO. Surfaces hardening
                            #    automations (audit scripts, integrity
                            #    checks, ...) that an auditor would expect
                            #    to see catalogued; collapsing each task's
                            #    relevant attributes into one Value cell
                            #    keeps the table readable. No catalog
                            #    lookup - every scheduled task pushed by a
                            #    GPO is in scope.
                            if ($oGPO.GPCFileSysPath) {
                                try {
                                    $hSTParams = @{ GPCFileSysPath = $oGPO.GPCFileSysPath }
                                    if ($Credential) { $hSTParams['Credential'] = $Credential }
                                    $aTasks = @(Get-ADGroupPolicyScheduledTask @hSTParams @hGPOParams)
                                    foreach ($oTask in $aTasks) {
                                        $aVal = @()
                                        if ($oTask.Action)               { $aVal += "Action=$($oTask.Action)" }
                                        if ($oTask.RunAs)                { $aVal += "RunAs=$($oTask.RunAs)" }
                                        if ($oTask.RunLevel)             { $aVal += "Level=$($oTask.RunLevel)" }
                                        if ($oTask.Command)              { $aVal += "Cmd=$($oTask.Command)" }
                                        if ($oTask.Arguments)            { $aVal += "Args=$($oTask.Arguments)" }
                                        if ($oTask.WorkingDir)           { $aVal += "WD=$($oTask.WorkingDir)" }
                                        if ($oTask.Triggers)             { $aVal += "Triggers=$($oTask.Triggers)" }
                                        if ($oTask.Enabled -eq $false)   { $aVal += "Enabled=False" }
                                        if ($oTask.Hidden  -eq $true)    { $aVal += "Hidden=True" }
                                        $aFiltered += [PSCustomObject][ordered]@{
                                            Section = 'GPP Scheduled Task'
                                            Setting = "$($oTask.Name) [$($oTask.Variant)]"
                                            Type    = 'GPP Scheduled Task'
                                            Value   = ($aVal -join '; ')
                                            _CMMC   = $null
                                        }
                                    }
                                } catch {
                                    Write-Warning "$sCallerName : $($oGPO.DisplayName) / ScheduledTasks.xml - $_"
                                }
                            }

                            # 5. Wireless / Wired network profiles
                            #    (msieee80211-Policy / msieee8023-Policy)
                            # Stored as AD objects under the GPO container,
                            # not in SYSVOL. CMMC scope: SC.L2-3.13.8
                            # (encryption in transit - WPA2/3 + AES) and
                            # IA.L2-3.5.3 (MFA - 802.1X with certificate-
                            # based EAP). CMMC label is derived per profile
                            # from observed protection level.
                            if ($oGPO.GPOId) {
                                try {
                                    $hNPParams = @{ GPOId = $oGPO.GPOId; Server = $sDomainName }
                                    if ($Credential) { $hNPParams['Credential'] = $Credential }
                                    $aNetProfiles = @(Get-ADGroupPolicyNetworkProfile @hNPParams)
                                    foreach ($oProf in $aNetProfiles) {
                                        $aVal = @()
                                        if ($oProf.SSID)                           { $aVal += "SSID=$($oProf.SSID)" }
                                        if ($oProf.ConnectionType)                 { $aVal += "ConnType=$($oProf.ConnectionType)" }
                                        if ($oProf.ConnectionMode)                 { $aVal += "ConnMode=$($oProf.ConnectionMode)" }
                                        if ($oProf.Authentication)                 { $aVal += "Auth=$($oProf.Authentication)" }
                                        if ($oProf.Encryption)                     { $aVal += "Enc=$($oProf.Encryption)" }
                                        if ($null -ne $oProf.UseOneX)              { $aVal += "802.1X=$($oProf.UseOneX)" }
                                        if ($oProf.OneXAuthMode)                   { $aVal += "AuthMode=$($oProf.OneXAuthMode)" }
                                        if ($oProf.EapMethodName)                  { $aVal += "EAP=$($oProf.EapMethodName)" }
                                        if ($null -ne $oProf.ValidateServerCertificate) { $aVal += "ValidateServer=$($oProf.ValidateServerCertificate)" }
                                        if ($oProf.TrustedRootHashCount -gt 0)     { $aVal += "TrustedRoots=$($oProf.TrustedRootHashCount)" }

                                        # CMMC mapping per profile:
                                        # - 802.1X with cert validation = IA-3.5.3 (MFA)
                                        # - WPA2/WPA3 + AES = SC-3.13.8 (encryption in transit)
                                        # - Open / WEP / no encryption = surfaced
                                        #   with $null CMMC so the auditor judges
                                        #   the anti-evidence directly.
                                        $sCMMC = $null
                                        if ($oProf.UseOneX -eq $true) {
                                            $sCMMC = 'IA.L2-3.5.3 - MULTIFACTOR AUTHENTICATION'
                                        } elseif ($oProf.Authentication -match '^(WPA2|WPA3)' -and $oProf.Encryption -in @('AES', 'GCMP256')) {
                                            $sCMMC = 'SC.L2-3.13.8 - ENCRYPTION OF CUI IN TRANSIT'
                                        }

                                        $aFiltered += [PSCustomObject][ordered]@{
                                            Section = 'Wireless'
                                            Setting = if ($oProf.PolicyType -eq 'Wireless') {
                                                "WLAN - $($oProf.ProfileName)$(if ($oProf.SSID -and $oProf.SSID -ne $oProf.ProfileName) { " (SSID: $($oProf.SSID))" })"
                                            } else {
                                                "Wired - $($oProf.ProfileName)"
                                            }
                                            Type    = "$($oProf.PolicyType) Profile"
                                            Value   = ($aVal -join '; ')
                                            _CMMC   = $sCMMC
                                        }
                                    }
                                } catch {
                                    Write-Warning "$sCallerName : $($oGPO.DisplayName) / Network profile - $_"
                                }
                            }

                            $oGPO | Add-Member -NotePropertyName FilteredSettings -NotePropertyValue $aFiltered -Force
                        }

                        # --- Per-GPO security-filter check ------------------
                        # Fetch every GPO's DACL once and record whether at
                        # least one Allow ACE grants the ApplyGroupPolicy
                        # extended right. No such ACE = "Empty Filtering": no
                        # principal can actually apply the GPO. The lookup
                        # feeds the per-link hasSecurityFilter column below.
                        # Map values: $true (has ACE) / $false (Empty Filtering)
                        # / $null (ACL unreadable - shown as Unknown).
                        $hGPOFilter = @{}
                        try {
                            $aAllDomainGPOs = @(Get-ADGroupPolicy @hDomainParams `
                                -Properties 'name', 'nTSecurityDescriptor' `
                                -SecurityMasks Dacl -ResultPageSize 1000)
                            $gApplyGroupPolicy = [Guid]'edacfd8f-ffb3-11d1-b41d-00a0c968f939'
                            foreach ($oGPO in $aAllDomainGPOs) {
                                if (-not $oGPO.name) { continue }
                                $bHas = $null
                                if ($oGPO.nTSecurityDescriptor) {
                                    try {
                                        $oSec = New-Object System.DirectoryServices.ActiveDirectorySecurity
                                        $oSec.SetSecurityDescriptorBinaryForm($oGPO.nTSecurityDescriptor)
                                        $aRules = $oSec.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
                                        $bHas = $false
                                        foreach ($oRule in $aRules) {
                                            if ($oRule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
                                            if ($oRule.ObjectType -ne $gApplyGroupPolicy) { continue }
                                            if (([int]$oRule.ActiveDirectoryRights -band [int][System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight) -eq 0) { continue }
                                            $bHas = $true
                                            break
                                        }
                                    } catch { $bHas = $null }
                                }
                                $hGPOFilter[$oGPO.name] = $bHas
                            }
                        } catch {
                            Write-Warning "$sCallerName : $sDomainName / GPO DACL enumeration - $_"
                        }

                        # OU-stats lookup table for the Empty-Target check.
                        $hOUStatsForDomain = if ($hOUStatsByDomain.ContainsKey($sDomainName)) {
                            $hOUStatsByDomain[$sDomainName]
                        } else {
                            [ordered]@{}
                        }

                        # Summary table — sorted hierarchically: domain root
                        # first, then each OU level, with siblings ordered
                        # alphabetically. The trick is to reverse the DN so
                        # alphabetical sort produces a tree order
                        # ("DC=grp,DC=stago,DC=au,OU=Sites,OU=Melbourne" reads
                        # parent → child, then plain string sort just works).
                        # GPOs without in-scope settings are grayed out.
                        # Track WMI filter usage per (domain, filter name) so the
                        # consolidated WMI Filters section below can report the count
                        # of referencing GPOs. Built incrementally - the dedup of
                        # filters happens at section-emit time, after every domain
                        # has contributed.
                        foreach ($oGPO in $aGPOData) {
                            if (-not $oGPO.WMIFilter) { continue }
                            $sUsageKey = "$($oGPO.WMIFilter)|$sDomainName"
                            if (-not $hWMIUsage.ContainsKey($sUsageKey)) { $hWMIUsage[$sUsageKey] = 0 }
                            $hWMIUsage[$sUsageKey]++
                        }

                        $aGPOSummary = @($aGPOData |
                            Sort-Object `
                                @{ Expression = {
                                    $aParts = @($_.LinkedTo -split ',')
                                    [array]::Reverse($aParts)
                                    ($aParts -join ',').ToLower()
                                } }, LinkOrder |
                            ForEach-Object {
                                # Per-GPO Empty-Filtering signal.
                                $bHasFilter = $null
                                if ($_.GPOId -and $hGPOFilter.ContainsKey($_.GPOId)) {
                                    $bHasFilter = $hGPOFilter[$_.GPOId]
                                }
                                # Per-link reachable audience: enabled users +
                                # computers under THIS link's OU (recursive).
                                # $null when the linked container isn't in the
                                # OU-stats table (e.g., cross-domain link or
                                # enumeration gap) - we don't flag Empty-Target
                                # in that case to avoid false positives.
                                $iReachable = $null
                                if ($_.LinkedTo -and $hOUStatsForDomain.Contains($_.LinkedTo)) {
                                    $oRow = $hOUStatsForDomain[$_.LinkedTo]
                                    $iReachable = ($oRow.users_recursive - $oRow.users_disabled_recursive) +
                                                  ($oRow.computers_recursive - $oRow.computers_disabled_recursive)
                                }
                                # A GPO link "effectively applies" when ALL of:
                                #   - at least one in-scope setting present
                                #   - GPO not fully disabled (flags != 3)
                                #   - at least one ApplyGroupPolicy ACE
                                #     (i.e. not Empty Filtering)
                                #   - this link's OU has > 0 enabled accounts
                                #     (i.e. not Empty Target)
                                # Per-link LinkEnabled is shown as its own
                                # column but is NOT folded into the flag - the
                                # export already shows linkEnabled = False
                                # explicitly, the row stays visible for audit.
                                $bEmptyFilter = ($bHasFilter -eq $false)
                                $bEmptyTarget = ($iReachable -eq 0)
                                $bApplies = ($_.FilteredSettings.Count -gt 0) -and
                                            ($_.GPOStatus -ne 'AllDisabled') -and
                                            (-not $bEmptyFilter) -and
                                            (-not $bEmptyTarget)
                                [PSCustomObject][ordered]@{
                                    linkedTo            = $_.LinkedTo
                                    linkOrder           = $_.LinkOrder
                                    displayName         = $_.DisplayName
                                    gpoId               = $_.GPOId
                                    gpoStatus           = $_.GPOStatus
                                    linkEnabled         = $_.LinkEnabled
                                    enforced            = $_.LinkEnforced
                                    wmiFilter           = $_.WMIFilter
                                    inScopeSettingCount = $_.FilteredSettings.Count
                                    hasSecurityFilter   = $bHasFilter
                                    reachableEnabled    = $iReachable
                                    effectivelyApplied  = $bApplies
                                }
                            })

                        # Per-perim filter: only keep links whose target
                        # DN belongs to this perim's ancestor set. In
                        # unscoped mode Ancestors is empty so we keep
                        # everything (the union $aGPOData already covers
                        # the relevant set thanks to FilterTargets above).
                        foreach ($oPerim in $aPerimsForDomain) {
                            $aPerimGPOSummary = if ($oPerim.Ancestors.Count -gt 0) {
                                @($aGPOSummary | Where-Object {
                                    $oPerim.Ancestors.ContainsKey(([string]$_.linkedTo).ToUpperInvariant())
                                })
                            } else {
                                $aGPOSummary
                            }
                            if ($aPerimGPOSummary.Count -eq 0) { continue }
                            $sId = "sec_$iTocIndex"; $iTocIndex++
                            $aSectionFiles += ConvertTo-HTMLSectionV2 -Title "GPO Links" -Id $sId `
                                -Data $aPerimGPOSummary -Tab $oPerim.Tab -Context $sDomainName `
                                -NameProperty 'displayName' -DetectAllColumns -NoSort `
                                -DisabledFlagProperty 'effectivelyApplied' `
                                -HiddenCols @('gpoId') `
                                -LinkableColumns @('displayName', 'wmiFilter', 'linkedTo') `
                                -RowFilters @(
                                    @{ Label = 'Hide GPO links with no effective application (no in-scope settings or GPO AllDisabled)'; HideFlag = 'd'; Default = $true }
                                )
                            $iTotal += $aPerimGPOSummary.Count
                        }
                        Write-Host "$sDomainName : $($aGPOData.Count) GPO link(s) across the domain" -ForegroundColor Cyan

                        # Detail sections for GPOs with in-scope settings.
                        # A single GPO linked to multiple OUs shows up multiple
                        # times in $aGPOData (once per link). Dedupe by GPOId so
                        # the settings panel only renders one section per GPO.
                        $hSeenGPO = @{}
                        $aUniqueGPOs = @(
                            $aGPOData |
                                Where-Object { $_.FilteredSettings.Count -gt 0 } |
                                Where-Object {
                                    # Guard against null/empty GPOId (cross-domain
                                    # fallback) — Hashtable.ContainsKey($null) throws.
                                    $sKey = if ($_.GPOId) { $_.GPOId } else { $_.GPCFileSysPath }
                                    if (-not $sKey) { return $true }
                                    if ($hSeenGPO.ContainsKey($sKey)) { return $false }
                                    $hSeenGPO[$sKey] = $true
                                    return $true
                                }
                        )
                        # Cross-domain dedup: instead of emitting one panel
                        # per (domain, GPO), accumulate into the forest-wide
                        # map keyed by "<DisplayName>|<fingerprint of
                        # rendered rows>". Identical replicas across
                        # domains collapse to one entry; same-name GPOs
                        # whose settings differ across domains become
                        # separate entries (different fingerprint -> new
                        # key). Emission happens after the per-domain
                        # loop closes, in the gpo tab.
                        foreach ($oGPO in $aUniqueGPOs) {
                            $aSettingsData = @($oGPO.FilteredSettings | ForEach-Object {
                                # Catalog-sourced rows carry their CMMC label
                                # in _CMMC; legacy rows fall back to the
                                # name/section-driven Get-CMMCControl lookup.
                                $sCMMC = $_._CMMC
                                if (-not $sCMMC) {
                                    $sCMMC = Get-CMMCControl -Setting $_.Setting -Section $_.Section
                                }
                                [PSCustomObject][ordered]@{
                                    section = $_.Section
                                    setting = $_.Setting
                                    type    = $_.Type
                                    value   = $_.Value
                                    cmmc    = $sCMMC
                                }
                            })

                            # Stable fingerprint of the rendered rows.
                            # Sort first so two domains that emitted the
                            # same FilteredSettings in different orders
                            # still collide. MD5 is fine here (not a
                            # security boundary, just a content key).
                            $aFPLines = @($aSettingsData | ForEach-Object {
                                "$($_.section)|$($_.setting)|$($_.type)|$($_.value)|$($_.cmmc)"
                            } | Sort-Object)
                            $sFP = $null
                            $oMD5 = [System.Security.Cryptography.MD5]::Create()
                            try {
                                $aHash = $oMD5.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(($aFPLines -join "`n")))
                                $sFP   = ([BitConverter]::ToString($aHash) -replace '-', '').Substring(0, 16)
                            } finally { $oMD5.Dispose() }

                            $sForestKey = "$($oGPO.DisplayName)|$sFP"
                            if (-not $hForestGPOByKey.Contains($sForestKey)) {
                                $hForestGPOByKey[$sForestKey] = @{
                                    DisplayName  = $oGPO.DisplayName
                                    SettingsData = $aSettingsData
                                    Domains      = @()
                                }
                            }
                            if ($sDomainName -notin $hForestGPOByKey[$sForestKey].Domains) {
                                $hForestGPOByKey[$sForestKey].Domains += $sDomainName
                            }

                            Write-Host "$sDomainName : GPO '$($oGPO.DisplayName)' - $($oGPO.FilteredSettings.Count) in-scope setting(s)" -ForegroundColor Cyan
                        }

                    } else {
                        Write-Host "$sDomainName : No GPO links found in the domain" -ForegroundColor Yellow
                    }
                } catch {
                    Write-Warning "$sCallerName : $sDomainName / GPO Links - $_"
                }

                # Close the per-domain PSSession opened above (if any). Errors
                # are swallowed - if the session already died on its own, the
                # warning would be noise.
                if ($oRemoteSession) {
                    Remove-PSSession $oRemoteSession -ErrorAction SilentlyContinue
                    $oRemoteSession = $null
                }
            }

            # ===== WMI FILTERS (deduplicated across forest) =====
            # Walks every domain, enumerates its msWMI-Som objects via
            # Get-ADWMIFilter (list mode), and collapses identical filters
            # — same Name and same set of WQL queries — into a single row
            # listing every domain where the filter is present. Drift
            # cases (same name, different queries between domains)
            # intentionally produce separate rows so cross-domain
            # inconsistencies remain visible to the auditor.
            $hWMIFilters = [ordered]@{}

            $iWMIIdx = 0
            foreach ($oDomain in $aDomains) {
                $iWMIIdx++
                $sDomainName = $oDomain.Name
                Write-Progress -Activity $sCallerName -Status "$sDomainName - WMI Filters..." `
                    -PercentComplete (Get-DomainStepProgress -Idx $iWMIIdx -Count $iDomainCount -Start 65 -End 68 -Step 0.0)

                try {
                    $hWFParams = @{ Server = $sDomainName }
                    if ($Credential) { $hWFParams['Credential'] = $Credential }
                    $aFilters = @(Get-ADWMIFilter @hWFParams)

                    foreach ($oFilter in $aFilters) {
                        # Display: "[<lang> on <ns>]\n<query>" per query, blank line between
                        # queries. Includes the WMI namespace so the auditor sees the tree
                        # location of each WQL probe (root\CIMv2 vs root\RSOP\Computer etc.).
                        $aDisplayLines = if ($oFilter.QueryDetails) {
                            $oFilter.QueryDetails | ForEach-Object {
                                "[$($_.Language) on $($_.Namespace)]`n$($_.Query)"
                            }
                        } else {
                            $oFilter.Queries   # fallback, pre-QueryDetails
                        }
                        $sQueries  = ($aDisplayLines -join "`n`n")
                        # Dedup key uses raw WQL only (no formatting metadata) so identical
                        # filters across domains collapse cleanly.
                        $sDedupKey = "$($oFilter.Name)|$(($oFilter.Queries) -join "`n")"

                        if (-not $hWMIFilters.Contains($sDedupKey)) {
                            $hWMIFilters[$sDedupKey] = [PSCustomObject][ordered]@{
                                Name         = $oFilter.Name
                                Description  = $oFilter.Description
                                Author       = $oFilter.Author
                                CreationDate = $oFilter.CreationDate
                                ChangeDate   = $oFilter.ChangeDate
                                Queries      = $sQueries
                                Domains      = @()
                                UsedByGPOs   = 0
                            }
                        }
                        $hWMIFilters[$sDedupKey].Domains += $sDomainName

                        # Add this domain's GPO usage for the filter. $hWMIUsage was
                        # populated by the per-domain GPO Links loop above.
                        $sUsageKey = "$($oFilter.Name)|$sDomainName"
                        if ($hWMIUsage.ContainsKey($sUsageKey)) {
                            $hWMIFilters[$sDedupKey].UsedByGPOs += $hWMIUsage[$sUsageKey]
                        }
                    }
                    Write-Host "$sDomainName : $($aFilters.Count) WMI filter(s) collected" -ForegroundColor Cyan
                } catch {
                    Write-Warning "$sCallerName : $sDomainName / WMI Filters - $_"
                }
            }

            if ($hWMIFilters.Count -gt 0) {
                $aWMIData = @($hWMIFilters.Values | Sort-Object Name | ForEach-Object {
                    [PSCustomObject][ordered]@{
                        name         = $_.Name
                        description  = $_.Description
                        author       = $_.Author
                        creationDate = $_.CreationDate
                        changeDate   = $_.ChangeDate
                        domains      = ($_.Domains -join ', ')
                        gposUsing    = $_.UsedByGPOs
                        queries      = $_.Queries
                        inUse        = $_.UsedByGPOs -gt 0
                    }
                })

                # Forest-wide section emitted once per perim. Filters
                # that no GPO references at all are flagged via
                # DisabledFlagProperty so the row checkbox can hide
                # them by default - the auditor focuses on filters
                # that actually constrain a GPO; unused ones are
                # dead weight.
                foreach ($oPerim in $hPerimData.Values) {
                    $sId = "sec_$iTocIndex"; $iTocIndex++
                    $aSectionFiles += ConvertTo-HTMLSectionV2 -Title "WMI Filters" -Id $sId `
                        -Data $aWMIData -Tab $oPerim.Tab `
                        -NameProperty 'name' -DetectAllColumns `
                        -DisabledFlagProperty 'inUse' `
                        -RowFilters @(
                            @{ Label = 'Hide WMI filters not referenced by any GPO'; HideFlag = 'd'; Default = $true }
                        )
                    $iTotal += $aWMIData.Count
                }
                Write-Host "WMI Filters : $($hWMIFilters.Count) unique filter(s) across forest" -ForegroundColor Cyan
            }

            # ===== DEDUPLICATED PER-GPO DETAIL PANELS =====
            # Cross-domain dedup of per-GPO panels collected during the
            # per-domain loop above. Same key = same DisplayName + same
            # rendered rows; the matching domains list goes into the
            # section Context, which ConvertTo-HTMLSectionV2 renders as
            # the subtitle "<GPO Name> -- <dom1, dom2, ...>". Same-name
            # GPOs with divergent settings end up as separate keys and
            # appear as distinct panels in the tab.
            if ($hForestGPOByKey.Count -gt 0) {
                # Sort by DisplayName first, then domain list, so the
                # TOC order is predictable and same-name variants sit
                # next to each other.
                $aSortedKeys = @($hForestGPOByKey.Keys |
                    Sort-Object @{ Expression = { $hForestGPOByKey[$_].DisplayName } },
                                @{ Expression = { ($hForestGPOByKey[$_].Domains | Sort-Object) -join ',' } })

                foreach ($sKey in $aSortedKeys) {
                    $hEntry = $hForestGPOByKey[$sKey]
                    $sDomains = ($hEntry.Domains | Sort-Object) -join ', '
                    $sId = "sec_$iTocIndex"
                    $iTocIndex++
                    # Title = raw DisplayName so the LinkableColumns
                    # navigation from the GPO Links table (in the
                    # security tab) still resolves. When several
                    # variants share a name, navigation lands on the
                    # first match - the auditor sees the others
                    # immediately below in the TOC.
                    $aSectionFiles += ConvertTo-HTMLSectionV2 -Title $hEntry.DisplayName -Id $sId `
                        -Data $hEntry.SettingsData -Tab $sGPOTab -Context $sDomains `
                        -NameProperty 'setting' -DetectAllColumns
                    $iTotal += $hEntry.SettingsData.Count
                }
                Write-Host "GPO Catalog : $($hForestGPOByKey.Count) unique GPO panel(s) across forest" -ForegroundColor Cyan
            }
        }

        # ===== GENERATE HTML REPORT =====
        if ($aSectionFiles.Count -eq 0) {
            Write-Warning "$sCallerName : No data collected, skipping report generation."
            return
        }

        Write-Progress -Activity $sCallerName -Status "Generating HTML report..." `
            -PercentComplete (Get-PhaseProgress -Start 93 -End 99 -Sub 0.0)

        # Build per-tab domain context map (forest hierarchy) for sidebar filters.
        # Each perim tab gets its own context list - only that perim's
        # in-scope domains plus their hierarchy ancestors, so the
        # sidebar Domain dropdown stays honest about what the tab
        # actually reports on.
        $hContexts = @{}
        $hContextLabels = @{}
        if ($IncludeSecurityPolicies) {
            foreach ($oPerim in $hPerimData.Values) {
                if ($oPerim.DomainContexts -and $oPerim.DomainContexts.Count -gt 0) {
                    $hContexts[$oPerim.Tab] = $oPerim.DomainContexts
                    $hContextLabels[$oPerim.Tab] = "Domain"
                }
            }
        }
        if ($IncludeTimeSynchronization -and $aDomainContexts -and $aDomainContexts.Count -gt 0) {
            $hContexts[$sTimeTab] = $aDomainContexts
            $hContextLabels[$sTimeTab] = "Domain"
        }

        $oSW.Stop()
        $sReportTitle = "AD Security Export - $sTimestamp"
        $sReportBrand = "AD Security"
        $oReport = New-HTMLReport -Title $sReportTitle `
            -Brand $sReportBrand `
            -DeviceInfo "Active Directory" `
            -SectionFiles $aSectionFiles `
            -Tabs $aTabs `
            -Contexts $hContexts `
            -ContextLabels $hContextLabels `
            -AccentColor "#1565c0" `
            -FilePath $sFilePath `
            -ObjectCount $iTotal `
            -GenerationDuration $oSW.Elapsed

        Write-Progress -Activity $sCallerName -Completed

        Write-Host "AD Security report exported: $sFilePath ($iTotal objects)" -ForegroundColor Green

        return $oReport
    }
}
