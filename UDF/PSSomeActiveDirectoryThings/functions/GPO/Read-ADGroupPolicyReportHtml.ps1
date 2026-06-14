function Read-ADGroupPolicyReportHtml {
    <#
    .SYNOPSIS
        Parses a GPMC "Save Report (HTML)" output and emits one
        PSCustomObject per configured setting.

    .DESCRIPTION
        GPMC saves GPO reports as UTF-16 LE HTML with a predictable
        structure: a top-level <div class="he0_expanded"> opens each
        half ("Computer Configuration", "User Configuration"), then
        nested heN_expanded headers build the breadcrumb path, and
        settings live inside tables (info3 for Administrative
        Templates; info / subtable for Security Settings, Preferences
        / Registry, Scheduled Tasks, Restricted Groups, ...).

        This function walks the document once and emits one row per
        CONFIGURED setting. Unconfigured rows ("Not Configured",
        empty placeholders, table-header rows) are skipped. Coverage:

        - Administrative Templates : via the gpmc_settingName /
          gpmc_settingPath span attributes the GPMC export embeds on
          every row. The path comes straight from gpmc_settingPath so
          the Computer / User prefix is already correct, and
          multi-element settings (a single Admin Template with several
          sub-parameters) emit their children as "  -> child" rows.

        - Security Settings : every info-class table is parsed. The
          containing section title is mapped to its canonical path
          (Account Policies / Local Policies / Event Log /
          Restricted Groups / Registry / File System / System Services
          / Public Key Policies / Windows Firewall profiles +
          Inbound / Outbound / Connection rules / Advanced Audit
          Configuration). Unknown titles fall back to
          "<half> / Security Settings / <title>".

        - GPP Preferences / Registry : the five canonical rows (Hive,
          Key path, Value name, Value type, Value data) are pulled
          together. RegistryHint is set to "HKLM\path!ValueName"
          (or HKCU\... per the configured hive).

        - GPP marker-only headers : Scheduled Tasks, Power Options,
          Local Users / Groups, NT Services, Files / Folders /
          Shortcuts, Drive Maps, Internet Settings, Folder Options,
          Printers, Start Menu. Each emits a single placeholder row
          so the caller knows the GPO touches that preference area;
          richer detail is read at run time by the dedicated
          extractor helpers (Get-ADGroupPolicyScheduledTask,
          Get-ADGroupPolicyLocalGroupMembership, ...).

        - Security Settings / System Services rows rendered as
          "Service Name (Startup Mode: X)".

        - Unmatched sections : any he3-level title that doesn't
          match the parser's known patterns is emitted as a row
          under Section "<half> / Unmatched" with Value
          "(parser does not recognise this section - extend
          Read-ADGroupPolicyReportHtml)". This keeps new GPMC
          categories visible in the output rather than dropped
          silently. Pass -ExcludeUnmatched to suppress them.

        Every emitted Section path is prefixed with the half name
        ("Computer Configuration" or "User Configuration") that
        contains the match position. This makes the function work
        for User Configuration GPOs (Office, Edge, OneDrive,
        Drive Maps, Start Menu customisation, ...) without
        misattributing them to the Computer side.

        Each row carries a per-file ComputerConfigState /
        UserConfigState ('Enabled' | 'Disabled' | 'Unknown') so the
        caller can filter dormant halves of the GPO before further
        analysis.

    .PARAMETER Path
        File path to a GPMC HTML report (.htm or .html), or a folder
        containing one or more reports (non-recursive: only direct
        children are read).

    .PARAMETER Filter
        File-name filter when -Path is a folder. Defaults to "*.htm".

    .PARAMETER ExcludeUnmatched
        Skip the "unmatched" placeholder rows for he3 section titles
        the parser does not recognise. Use when the consumer only
        wants confirmed-data rows and is willing to accept that new
        GPMC categories will be silently dropped.

    .OUTPUTS
        PSCustomObject[] with properties:
            GPO                  : filename without extension
            ComputerConfigState  : 'Enabled' | 'Disabled' | 'Unknown'
            UserConfigState      : 'Enabled' | 'Disabled' | 'Unknown'
            Section              : "<half> / ... / leaf"
            Setting              : canonical setting name (or
                                   "  -> child" for Admin Template
                                   sub-elements)
            Value                : displayed value
            RegistryHint         : "HKLM\path!ValueName" /
                                   "HKCU\..." for GPP Registry; ""
                                   otherwise

        Files that fail to read emit a Verbose message and contribute
        no rows; the caller can compare its input file list against
        the distinct GPO property of the result to detect those.

    .EXAMPLE
        Read-ADGroupPolicyReportHtml -Path 'C:\Temp\hardening\Lot 4'

        Returns every configured setting from every .htm in the
        folder, plus placeholder rows for any unrecognised sections.

    .EXAMPLE
        Read-ADGroupPolicyReportHtml -Path 'C:\Temp\hardening\Lot 4' -ExcludeUnmatched |
            Where-Object Section -match 'OneDrive' |
            Group-Object Setting -NoElement |
            Sort-Object Count -Descending

        Settings touching OneDrive, ranked by how many GPOs configure
        them. -ExcludeUnmatched drops the diagnostic placeholders so
        the Group-Object count is purely data.

    .EXAMPLE
        Read-ADGroupPolicyReportHtml -Path 'C:\Reports' |
            Where-Object Section -match '/ Unmatched$'

        Surface every GPMC section the parser couldn't categorise -
        useful when extending the parser to cover a new GPMC
        category.

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-05-28) - Initial version. Covers Administrative
                             Templates, Security Settings tables,
                             GPP Preferences Registry, common GPP
                             markers and Security Settings System
                             Services. Computer / User half is
                             resolved by match position so reports
                             that configure both halves emit each
                             setting under the correct path. Sections
                             outside the parser's known patterns are
                             surfaced as "Unmatched" placeholder rows
                             (opt-out via -ExcludeUnmatched) so new
                             GPMC categories don't disappear
                             silently.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('FullName')]
        [string]$Path,

        [string]$Filter = '*.htm',

        [switch]$ExcludeUnmatched
    )

    Begin {
        # Resolve a file path or folder path to a list of .htm/.html
        # files. Folder lookup is shallow (non-recursive) to match the
        # usual "one batch = one folder" workflow.
        function Resolve-GpmcReportFiles {
            Param([string]$P, [string]$F)
            if (Test-Path -LiteralPath $P -PathType Container) {
                return @(Get-ChildItem -LiteralPath $P -Filter $F -File | Sort-Object Name)
            }
            if (Test-Path -LiteralPath $P -PathType Leaf) {
                return @(Get-Item -LiteralPath $P)
            }
            Write-Warning "Read-ADGroupPolicyReportHtml : path not found - $P"
            return @()
        }

        # Short hive name for the GPP Registry "Hive" column. GPMC
        # writes the long form; the short form keeps RegistryHint
        # compact and matches the catalog convention elsewhere.
        function ConvertTo-ShortHive {
            Param([string]$Hive)
            switch ($Hive) {
                'HKEY_LOCAL_MACHINE'  { 'HKLM' }
                'HKEY_CURRENT_USER'   { 'HKCU' }
                'HKEY_USERS'          { 'HKU'  }
                'HKEY_CLASSES_ROOT'   { 'HKCR' }
                'HKEY_CURRENT_CONFIG' { 'HKCC' }
                default               { $Hive }
            }
        }

        # Section-title patterns the parser handles via its main
        # extractors (Security Settings switch or GPP markers).
        # When the unmatched-row emission scans every he3 title, any
        # title that matches one of these is treated as "already
        # covered" and NOT emitted as an unmatched placeholder.
        $aHandledPatterns = @(
            '^Password Policy$', '^Account Lockout Policy$', '^Kerberos Policy$'
            '^Audit Policy$', '^User Rights Assignment$', '^Security Options$'
            '^Event Log$', '^Restricted Groups$', '^System Services$'
            '^Registry$', '^File System$'
            'Public Key Policies', 'Profile Settings$'
            '^(Connection Security Settings|Inbound Rules|Outbound Rules)$'
            '^Advanced Audit Configuration'
            '^Scheduled Task', '^Power (Plan|Options|Scheme)'
            '^(Local Group|Local User)', '^NT Service'
            '^(File|Folder|Shortcut)\b', '^Drive Map'
            '^Internet Settings', '^Folder Options', '^Printers?', '^Start Menu'
        )

        # Structural titles to ignore for the unmatched scan. These
        # are container headers (parents of leaf settings), not leaf
        # categories - their presence is structural and doesn't need
        # a row. The "/" pattern catches Admin Template sub-paths
        # (e.g. "Windows Components/Internet Explorer") that GPMC
        # renders as he3 headers but whose actual settings have
        # already been harvested via gpmc_settingPath in pass 1.
        $aIgnoredPatterns = @(
            '^Computer Configuration \('
            '^User Configuration \('
            '^Policies$'
            '^Preferences$'
            '^Windows Settings$'
            '^Software Settings$'
            '^Administrative Templates$'
            '^Security Settings$'
            '^Control Panel Settings$'
            '/'
        )
    }

    Process {
        $aFiles = Resolve-GpmcReportFiles -P $Path -F $Filter
        foreach ($oFile in $aFiles) {
            $sName = $oFile.BaseName
            $sContent = $null
            try {
                # GPMC saves as UTF-16 LE; -Encoding Unicode is the
                # canonical default. Future GPMC variants emitting
                # UTF-8 would need BOM-sniffing here.
                $sContent = Get-Content -LiteralPath $oFile.FullName -Encoding Unicode -Raw
            } catch {
                Write-Verbose "Read-ADGroupPolicyReportHtml : cannot read '$($oFile.FullName)' - $_"
                continue
            }
            if ([string]::IsNullOrEmpty($sContent)) {
                Write-Verbose "Read-ADGroupPolicyReportHtml : empty content - $($oFile.FullName)"
                continue
            }

            # Computer / User Configuration enabled state from the
            # GPMC header. Lets the caller filter dormant halves.
            $sCompState = if     ($sContent -match 'Computer Configuration \(Enabled\)')  { 'Enabled'  }
                          elseif ($sContent -match 'Computer Configuration \(Disabled\)') { 'Disabled' }
                          else                                                            { 'Unknown'  }
            $sUserState = if     ($sContent -match 'User Configuration \(Enabled\)')      { 'Enabled'  }
                          elseif ($sContent -match 'User Configuration \(Disabled\)')     { 'Disabled' }
                          else                                                            { 'Unknown'  }

            # Position-based half resolution. The two he0_expanded
            # headers split the document; a setting whose document
            # position is >= iUserPos belongs to the User half,
            # otherwise to the Computer half. Either may be missing
            # in tooling-trimmed exports; we default to Computer
            # when the User marker is not reachable.
            $iCompPos = -1
            $iUserPos = -1
            $oCompMatch = [regex]::Match($sContent, '<div class="he0_expanded"><span class="sectionTitle"[^>]*>Computer Configuration \(')
            if ($oCompMatch.Success) { $iCompPos = $oCompMatch.Index }
            $oUserMatch = [regex]::Match($sContent, '<div class="he0_expanded"><span class="sectionTitle"[^>]*>User Configuration \(')
            if ($oUserMatch.Success) { $iUserPos = $oUserMatch.Index }

            # Closure used by each subsequent section to derive the
            # "Computer Configuration" / "User Configuration" prefix
            # from a match position in the document.
            $script:iCompPos = $iCompPos
            $script:iUserPos = $iUserPos
            $fnHalf = {
                Param([int]$Pos)
                if ($script:iUserPos -ge 0 -and $Pos -ge $script:iUserPos) { return 'User Configuration' }
                return 'Computer Configuration'
            }

            # Per-file row accumulator. Emitted (deduplicated) at the
            # end of the file iteration so the same Section + Setting
            # + Value cannot surface twice when GPMC documents it
            # from two parallel tables.
            $aRows = New-Object 'System.Collections.Generic.List[psobject]'

            # ==== 1. Administrative Templates ======================
            # Every Admin Template row has a span with both
            # gpmc_settingName (the leaf label) and gpmc_settingPath
            # (the full breadcrumb, already prefixed with the right
            # half). The value cell is the next <td>. A multi-element
            # setting embeds its sub-parameters in a sibling
            # subtable_frame table; we walk that and emit each child
            # as a "  -> child" row.
            $oAdmxRe = [regex]'gpmc_settingName="(?<name>[^"]*)"\s+gpmc_settingPath="(?<path>[^"]*)"[^>]*>(?:[^<]*)</span>\s*</td>\s*<td>(?<val>.*?)</td>'
            foreach ($oM in $oAdmxRe.Matches($sContent)) {
                $sSection = ($oM.Groups['path'].Value -replace '/', ' / ')
                $sSetting = ConvertFrom-HtmlText $oM.Groups['name'].Value
                $sValue   = ConvertFrom-HtmlText $oM.Groups['val'].Value
                $aRows.Add([PSCustomObject][ordered]@{
                    GPO                 = $sName
                    ComputerConfigState = $sCompState
                    UserConfigState     = $sUserState
                    Section             = $sSection
                    Setting             = $sSetting
                    Value               = $sValue
                    RegistryHint        = ''
                })

                # Look-ahead for the optional subtable_frame, bounded
                # by the next gpmc_settingName occurrence so we don't
                # grab a sibling setting's frame by accident. 6000-char
                # cap is a defensive belt against malformed reports.
                $iAfter = $oM.Index + $oM.Length
                $iNext  = $sContent.IndexOf('gpmc_settingName=', $iAfter)
                if ($iNext -lt 0) { $iNext = $sContent.Length }
                $iEnd     = [Math]::Min($iNext, $iAfter + 6000)
                $sSegment = $sContent.Substring($iAfter, $iEnd - $iAfter)

                $oFrame = [regex]::Match($sSegment, '(?s)<table class="subtable_frame"[^>]*>(?<body>.*?)</table>')
                if ($oFrame.Success) {
                    $sBody = $oFrame.Groups['body'].Value
                    foreach ($oC in [regex]::Matches($sBody, '(?s)<tr>\s*<td>(?<k>.*?)</td>\s*<td>(?<v>.*?)</td>\s*</tr>')) {
                        $sSubKey = ConvertFrom-HtmlText $oC.Groups['k'].Value
                        $sSubVal = ConvertFrom-HtmlText $oC.Groups['v'].Value
                        if ($sSubKey -or $sSubVal) {
                            $aRows.Add([PSCustomObject][ordered]@{
                                GPO                 = $sName
                                ComputerConfigState = $sCompState
                                UserConfigState     = $sUserState
                                Section             = $sSection
                                Setting             = "  -> $sSubKey"
                                Value               = $sSubVal
                                RegistryHint        = ''
                            })
                        }
                    }
                }
            }

            # ==== 2. Security Settings (info-class tables) =========
            # Tables appear under <span class="sectionTitle"> headers
            # with <td>Policy</td><td>Setting</td> rows (no
            # gpmc_settingName). The half prefix comes from the
            # title's position in the document; the title itself
            # maps to its canonical Security Settings sub-path via a
            # small switch (unknown titles fall back to a flat
            # "<half> / Security Settings / <title>").
            $aTitles = [regex]::Matches($sContent, '<span class="sectionTitle"[^>]*>(?<title>[^<]+)</span>')
            for ($iT = 0; $iT -lt $aTitles.Count; $iT++) {
                $oTm = $aTitles[$iT]
                $sTitle = ConvertFrom-HtmlText $oTm.Groups['title'].Value
                $iBlockStart = $oTm.Index + $oTm.Length
                $iBlockEnd   = if ($iT -lt $aTitles.Count - 1) { $aTitles[$iT + 1].Index } else { $sContent.Length }
                $sBlock      = $sContent.Substring($iBlockStart, $iBlockEnd - $iBlockStart)
                $sHalf       = & $fnHalf $oTm.Index

                $sSection = switch -Regex ($sTitle) {
                    '^(Password Policy|Account Lockout Policy|Kerberos Policy)$' {
                        "$sHalf / Policies / Windows Settings / Security Settings / Account Policies / $sTitle"
                    }
                    '^(Audit Policy|User Rights Assignment|Security Options)$' {
                        "$sHalf / Policies / Windows Settings / Security Settings / Local Policies / $sTitle"
                    }
                    '^Event Log$'                                   { "$sHalf / Policies / Windows Settings / Security Settings / Event Log" }
                    '^Restricted Groups$'                           { "$sHalf / Policies / Windows Settings / Security Settings / Restricted Groups" }
                    '^System Services$'                             { "$sHalf / Policies / Windows Settings / Security Settings / System Services" }
                    '^Registry$'                                    { "$sHalf / Policies / Windows Settings / Security Settings / Registry" }
                    '^File System$'                                 { "$sHalf / Policies / Windows Settings / Security Settings / File System" }
                    'Public Key Policies'                           { "$sHalf / Policies / Windows Settings / Security Settings / Public Key Policies / $sTitle" }
                    'Profile Settings$'                             { "$sHalf / Policies / Windows Settings / Security Settings / Windows Firewall with Advanced Security / $sTitle" }
                    '^(Connection Security Settings|Inbound Rules|Outbound Rules)$' {
                        "$sHalf / Policies / Windows Settings / Security Settings / Windows Firewall with Advanced Security / $sTitle"
                    }
                    '^Advanced Audit Configuration'                 { "$sHalf / Policies / Windows Settings / Security Settings / Advanced Audit Configuration" }
                    default                                         { "$sHalf / Security Settings / $sTitle" }
                }

                # Iterate every <table class="info"> in this block.
                # Skip ones containing gpmc_settingName (already
                # harvested by the Admin Template pass).
                foreach ($oTbl in [regex]::Matches($sBlock, '(?s)<table class="info"[^>]*>(?<tbody>.*?)</table>')) {
                    $sTbody = $oTbl.Groups['tbody'].Value
                    if ($sTbody -match 'gpmc_settingName') { continue }

                    $oRowRe = [regex]'(?s)<tr>\s*<td>(?<col1>(?:(?!<th).)*?)</td>\s*<td>(?<col2>.*?)</td>(?:\s*<td>(?<col3>.*?)</td>)?\s*</tr>'
                    foreach ($oR in $oRowRe.Matches($sTbody)) {
                        $s1 = ConvertFrom-HtmlText $oR.Groups['col1'].Value
                        $s2 = ConvertFrom-HtmlText $oR.Groups['col2'].Value
                        if (-not $s1) { continue }
                        if ($s1 -eq 'Policy' -or $s1 -eq 'Setting') { continue }   # header row
                        $aRows.Add([PSCustomObject][ordered]@{
                            GPO                 = $sName
                            ComputerConfigState = $sCompState
                            UserConfigState     = $sUserState
                            Section             = $sSection
                            Setting             = $s1
                            Value               = $s2
                            RegistryHint        = ''
                        })
                    }
                }
            }

            # ==== 3. GPP Preferences / Registry ====================
            # Each registry item appears as a he4-headed group with a
            # subtable holding the five canonical rows. The half
            # prefix uses the document position so a Computer-half
            # block referencing an HKCU value still reads
            # "Computer Configuration / ..." - the half is the
            # structural location, the hive is just the data.
            $oRegRe = [regex]'(?s)<div class="he4[^"]*"><span class="sectionTitle"[^>]*>(?<group>[^<]+)</span>.*?<table class="subtable"[^>]*><tr><td>Hive</td><td>(?<hive>[^<]*)</td></tr>\s*<tr><td>Key path</td><td>(?<keypath>[^<]*)</td></tr>\s*<tr><td>Value name</td><td>(?<vname>[^<]*)</td></tr>\s*<tr><td>Value type</td><td>(?<vtype>[^<]*)</td></tr>\s*<tr><td>Value data</td><td>(?<vdata>[^<]*)</td></tr>'
            foreach ($oR in $oRegRe.Matches($sContent)) {
                $sShort = ConvertTo-ShortHive $oR.Groups['hive'].Value
                $sHint  = "$sShort\$($oR.Groups['keypath'].Value)!$($oR.Groups['vname'].Value)"
                $sHalf  = & $fnHalf $oR.Index
                $aRows.Add([PSCustomObject][ordered]@{
                    GPO                 = $sName
                    ComputerConfigState = $sCompState
                    UserConfigState     = $sUserState
                    Section             = "$sHalf / Preferences / Windows Settings / Registry"
                    Setting             = $oR.Groups['vname'].Value
                    Value               = "$($oR.Groups['vtype'].Value) = $(ConvertFrom-HtmlText $oR.Groups['vdata'].Value) ($(ConvertFrom-HtmlText $oR.Groups['group'].Value))"
                    RegistryHint        = $sHint
                })
            }

            # ==== 4. GPP marker-only headers =======================
            # Each marker emits a placeholder row with the detected
            # half. The Section template uses "{HALF}" so the
            # placeholder can be substituted per match position. The
            # exporter's run-time scanners pull richer detail; for
            # catalog triage the marker presence is enough.
            $aMarkers = @(
                @{ Re = '<div class="he3"><span class="sectionTitle"[^>]*>(?<h>Scheduled Task[^<]*)</span>';                       Section = '{HALF} / Preferences / Control Panel Settings / Scheduled Tasks';       Value = '(Scheduled task defined)' }
                @{ Re = '<div class="he3"><span class="sectionTitle"[^>]*>(?<h>(?:Power (?:Plan|Options|Scheme))[^<]*)</span>';   Section = '{HALF} / Preferences / Control Panel Settings / Power Options';         Value = '(Power options defined)' }
                @{ Re = '<div class="he3"><span class="sectionTitle"[^>]*>(?<h>Local Group[^<]*|Local User[^<]*)</span>';        Section = '{HALF} / Preferences / Control Panel Settings / Local Users and Groups'; Value = '(Group/user definition)' }
                @{ Re = '<div class="he3"><span class="sectionTitle"[^>]*>(?<h>NT Service[^<]*)</span>';                         Section = '{HALF} / Preferences / Control Panel Settings / Services';             Value = '(Service preference)' }
                @{ Re = '<div class="he3"><span class="sectionTitle"[^>]*>(?<h>(?:File|Folder|Shortcut)\b[^<]*)</span>';         Section = '{HALF} / Preferences / Windows Settings';                               Value = '(Preference item)' }
                @{ Re = '<div class="he3"><span class="sectionTitle"[^>]*>(?<h>Drive Map[^<]*)</span>';                          Section = '{HALF} / Preferences / Windows Settings / Drive Maps';                  Value = '(Drive mapping defined)' }
                @{ Re = '<div class="he3"><span class="sectionTitle"[^>]*>(?<h>Internet Settings[^<]*)</span>';                  Section = '{HALF} / Preferences / Control Panel Settings / Internet Settings';     Value = '(IE settings defined)' }
                @{ Re = '<div class="he3"><span class="sectionTitle"[^>]*>(?<h>Folder Options[^<]*)</span>';                     Section = '{HALF} / Preferences / Control Panel Settings / Folder Options';        Value = '(Folder options defined)' }
                @{ Re = '<div class="he3"><span class="sectionTitle"[^>]*>(?<h>Printers?[^<]*)</span>';                          Section = '{HALF} / Preferences / Control Panel Settings / Printers';              Value = '(Printer preference defined)' }
                @{ Re = '<div class="he3"><span class="sectionTitle"[^>]*>(?<h>Start Menu[^<]*)</span>';                         Section = '{HALF} / Preferences / Control Panel Settings / Start Menu';            Value = '(Start menu preference)' }
            )
            foreach ($hM in $aMarkers) {
                foreach ($oR in [regex]::Matches($sContent, $hM.Re)) {
                    $sHdr  = ConvertFrom-HtmlText $oR.Groups['h'].Value
                    $sHalf = & $fnHalf $oR.Index
                    $aRows.Add([PSCustomObject][ordered]@{
                        GPO                 = $sName
                        ComputerConfigState = $sCompState
                        UserConfigState     = $sUserState
                        Section             = ($hM.Section -replace '\{HALF\}', $sHalf)
                        Setting             = $sHdr
                        Value               = $hM.Value
                        RegistryHint        = ''
                    })
                }
            }

            # ==== 5. Security Settings / System Services ===========
            # Rendered as he4h "Service Name (Startup Mode: X)" -
            # distinct from the GPP "NT Service" preference marker.
            $oSvcRe = [regex]'<div class="he4h"><span class="sectionTitle"[^>]*>(?<svc>[^<]+?)\s*\(Startup Mode:\s*(?<mode>[^)]+)\)</span>'
            foreach ($oR in $oSvcRe.Matches($sContent)) {
                $sSvc  = ConvertFrom-HtmlText $oR.Groups['svc'].Value
                $sMode = ConvertFrom-HtmlText $oR.Groups['mode'].Value
                $sHalf = & $fnHalf $oR.Index
                $aRows.Add([PSCustomObject][ordered]@{
                    GPO                 = $sName
                    ComputerConfigState = $sCompState
                    UserConfigState     = $sUserState
                    Section             = "$sHalf / Policies / Windows Settings / Security Settings / System Services"
                    Setting             = $sSvc
                    Value               = "Startup Mode: $sMode"
                    RegistryHint        = ''
                })
            }

            # ==== 6. Unmatched he3 sections ========================
            # Surface every he3-level section title the parser does
            # not recognise as either handled (one of the well-known
            # sub-categories above) or structural (Computer / User
            # Configuration container, Policies, Preferences, ...).
            # Default behaviour ensures new GPMC categories appear
            # in the output rather than disappearing silently.
            if (-not $ExcludeUnmatched) {
                $oUnmatchedRe = [regex]'<div class="he3"><span class="sectionTitle"[^>]*>(?<title>[^<]+)</span>'
                foreach ($oR in $oUnmatchedRe.Matches($sContent)) {
                    $sTitle = ConvertFrom-HtmlText $oR.Groups['title'].Value
                    if (-not $sTitle) { continue }

                    $bHandled = $false
                    foreach ($p in $aHandledPatterns) { if ($sTitle -match $p) { $bHandled = $true; break } }
                    if ($bHandled) { continue }

                    $bIgnored = $false
                    foreach ($p in $aIgnoredPatterns) { if ($sTitle -match $p) { $bIgnored = $true; break } }
                    if ($bIgnored) { continue }

                    $sHalf = & $fnHalf $oR.Index
                    $aRows.Add([PSCustomObject][ordered]@{
                        GPO                 = $sName
                        ComputerConfigState = $sCompState
                        UserConfigState     = $sUserState
                        Section             = "$sHalf / Unmatched"
                        Setting             = $sTitle
                        Value               = '(parser does not recognise this section - extend Read-ADGroupPolicyReportHtml)'
                        RegistryHint        = ''
                    })
                }
            }

            # ==== Per-file dedup + emit ============================
            # Same Section + Setting + Value + RegistryHint = the
            # same row (GPMC occasionally documents a setting twice
            # from parallel tables).
            $hSeen = @{}
            foreach ($oRow in $aRows) {
                $sKey = "$($oRow.Section)|$($oRow.Setting)|$($oRow.Value)|$($oRow.RegistryHint)"
                if ($hSeen.ContainsKey($sKey)) { continue }
                $hSeen[$sKey] = $true
                $oRow
            }
        }
    }
}
