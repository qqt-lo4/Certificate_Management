function Get-ADGroupPolicyLocalGroupMembership {
    <#
    .SYNOPSIS
        Extracts local group memberships managed by a GPO.

    .DESCRIPTION
        Reads a GPO's SYSVOL folder and returns one object per local group
        membership directive defined by either of the two Group Policy
        mechanisms used to control local group membership:

        - Restricted Groups : Computer Configuration \ Policies \ Windows
          Settings \ Security Settings \ Restricted Groups. Parsed from the
          [Group Membership] section of
          Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf.

        - Group Policy Preferences (GPP) - Local Users and Groups : Computer
          Configuration \ Preferences \ Control Panel Settings \ Local Users
          and Groups. Parsed from Machine\Preferences\Groups\Groups.xml.

        Both sources are returned through a unified schema, with the .Source
        property identifying which mechanism produced the entry. The function
        returns ALL local groups managed by the GPO; filtering to a subset
        (e.g., privileged groups only) is the caller's responsibility.

        SIDs and friendly names are cross-resolved through
        System.Security.Principal where possible; resolution failures (e.g.,
        for orphaned domain accounts) leave the original value untouched.

    .PARAMETER GPCFileSysPath
        UNC path to the GPO's SYSVOL folder (gPCFileSysPath attribute).

    .PARAMETER Credential
        Optional PSCredential for SYSVOL access.

    .OUTPUTS
        PSCustomObject[] with properties:
            Source             ('Restricted Groups' | 'GPP')
            GroupSid           (well-known or domain SID, when resolvable)
            GroupName          (display name as found in the policy)
            ResolvedName       (NTAccount form of GroupSid, when resolvable)
            Action             ('ReplaceMembers' or 'MemberOf' for Restricted
                                Groups; 'Create'/'Update'/'Replace'/'Delete'
                                for GPP)
            NewName            (GPP rename target, when set)
            Description        (GPP, when set)
            DeleteAllUsers     (GPP)
            DeleteAllGroups    (GPP)
            RemoveOtherMembers (true when the directive replaces existing
                                membership rather than appending)
            Members            (@({Name; Sid; Action})) where Action is
                                'Add', 'Remove' or 'Set'
            ParentGroups       (@({Name; Sid})) — only for Restricted Groups
                                __Memberof entries

    .EXAMPLE
        Get-ADGroupPolicy -Identity "Workstations - Local Admins" -Properties gPCFileSysPath |
            ForEach-Object { Get-ADGroupPolicyLocalGroupMembership -GPCFileSysPath $_.gPCFileSysPath }

    .EXAMPLE
        # Filter to privileged local groups only
        Get-ADGroupPolicyLocalGroupMembership -GPCFileSysPath $oGPO.GPCFileSysPath |
            Where-Object { $_.GroupSid -in @('S-1-5-32-544','S-1-5-32-555') }

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        1.0.0 (2026-04-28) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$GPCFileSysPath,

        [AllowNull()]
        [PSCredential]$Credential,

        [AllowNull()]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    Process {
        # --- Helpers ---------------------------------------------------------
        # SID -> NTAccount string: delegated to the module-level
        # Resolve-ADSidName so the global cache is shared with every
        # other consumer of GptTmpl.inf principal lists (Export-AD's
        # Privilege Rights scan in particular).

        # NTAccount string -> SID. Returns $null on failure.
        function Resolve-NameSid {
            Param([string]$Name)
            if (-not $Name) { return $null }
            try {
                $oNt = New-Object System.Security.Principal.NTAccount($Name)
                return $oNt.Translate([System.Security.Principal.SecurityIdentifier]).Value
            } catch {
                return $null
            }
        }

        # Parse a "*SID" or "Domain\Name" / "Name" string into a {Sid; Name} pair.
        function Resolve-Principal {
            Param([string]$Token)
            $sToken = $Token.Trim()
            if (-not $sToken) { return $null }
            if ($sToken -match '^\*(?<sid>S-1-[\d-]+)$') {
                $sSid  = $Matches['sid']
                $sName = Resolve-ADSidName -Sid $sSid
                return [PSCustomObject][ordered]@{ Name = $sName; Sid = $sSid }
            } else {
                # Strip enclosing quotes if present
                $sName = $sToken.Trim('"')
                $sSid  = Resolve-NameSid -Name $sName
                return [PSCustomObject][ordered]@{ Name = $sName; Sid = $sSid }
            }
        }

        # =====================================================================
        # 1. Restricted Groups (GptTmpl.inf [Group Membership] section)
        # =====================================================================
        $aSettings = @()
        try {
            $hSecParams = @{ GPCFileSysPath = $GPCFileSysPath }
            if ($Credential) { $hSecParams['Credential'] = $Credential }
            if ($Session)    { $hSecParams['Session']    = $Session }
            $aSettings = @(Get-ADGroupPolicySecuritySettings @hSecParams)
        } catch {
            Write-Warning "Get-ADGroupPolicyLocalGroupMembership : GptTmpl.inf - $_"
        }
        $aGroupMembershipLines = @($aSettings | Where-Object { $_.Section -eq 'Group Membership' })

        # Aggregate the __Members and __Memberof lines per group identity.
        # In GptTmpl.inf the same group can have both forms, so we build one
        # unified entry rather than emitting two separate rows.
        $hGroups = [ordered]@{}

        foreach ($oLine in $aGroupMembershipLines) {
            if ($oLine.Setting -notmatch '^(?<group>.+)__(?<kind>Members|Memberof)$') { continue }

            $sGroupRaw = $Matches['group'].Trim('"')
            $sKind     = $Matches['kind']

            $oGroupId = Resolve-Principal -Token $sGroupRaw
            if (-not $oGroupId) { continue }

            $sKey = if ($oGroupId.Sid) { $oGroupId.Sid } else { "name:$($oGroupId.Name)" }

            if (-not $hGroups.Contains($sKey)) {
                $hGroups[$sKey] = [PSCustomObject][ordered]@{
                    Source             = 'Restricted Groups'
                    GroupSid           = $oGroupId.Sid
                    GroupName          = $oGroupId.Name
                    ResolvedName       = if ($oGroupId.Sid) { Resolve-ADSidName -Sid $oGroupId.Sid } else { $null }
                    Action             = $null
                    NewName            = $null
                    Description        = $null
                    DeleteAllUsers     = $null
                    DeleteAllGroups    = $null
                    RemoveOtherMembers = $false
                    Members            = @()
                    ParentGroups       = @()
                }
            }
            $oEntry = $hGroups[$sKey]

            # The value is a comma-separated list of principals. Empty strings
            # are valid and mean "no member" (Members) or "no parent" (Memberof).
            $aTokens = @()
            if ($oLine.Value) {
                $aTokens = @($oLine.Value -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
            }

            $aPrincipals = foreach ($sToken in $aTokens) {
                $oP = Resolve-Principal -Token $sToken
                if ($oP) { $oP }
            }

            if ($sKind -eq 'Members') {
                # __Members is authoritative: the listed accounts replace the
                # full membership of the group.
                $oEntry.Action             = 'ReplaceMembers'
                $oEntry.RemoveOtherMembers = $true
                $oEntry.Members            = @($oEntry.Members) + @(
                    $aPrincipals | ForEach-Object {
                        [PSCustomObject][ordered]@{ Name = $_.Name; Sid = $_.Sid; Action = 'Set' }
                    }
                )
            } else {
                # __Memberof: this group becomes a member of the listed parent
                # groups. Additive — does not affect existing memberships.
                if (-not $oEntry.Action) { $oEntry.Action = 'MemberOf' }
                $oEntry.ParentGroups = @($oEntry.ParentGroups) + @(
                    $aPrincipals | ForEach-Object {
                        [PSCustomObject][ordered]@{ Name = $_.Name; Sid = $_.Sid }
                    }
                )
            }
        }

        foreach ($oEntry in $hGroups.Values) { $oEntry }

        # =====================================================================
        # 2. GPP - Local Users and Groups (Groups.xml)
        # =====================================================================
        $sGroupsXml = Join-Path $GPCFileSysPath 'Machine\Preferences\Groups\Groups.xml'

        # Read the XML blob via Read-ADPolicyFile so -Session transparently
        # delegates the SYSVOL read to a remote host when needed. The XML
        # parse stays local on the casted string.
        $sXmlRaw = $null
        try {
            $sXmlRaw = Read-ADPolicyFile -Path $sGroupsXml -Mode TextRaw -Session $Session
        } catch {
            Write-Warning "Get-ADGroupPolicyLocalGroupMembership : cannot read '$sGroupsXml' - $_"
            return
        }
        if (-not $sXmlRaw) { return }
        $oXml = $null
        try {
            [xml]$oXml = $sXmlRaw
        } catch {
            Write-Warning "Get-ADGroupPolicyLocalGroupMembership : malformed XML at '$sGroupsXml' - $_"
            return
        }

        # GPP action codes (Properties/@action attribute)
        $hActionCode = @{
            'C' = 'Create'
            'R' = 'Replace'
            'U' = 'Update'
            'D' = 'Delete'
        }

        foreach ($oGroupNode in @($oXml.SelectNodes('//Group'))) {
            $oProps = $oGroupNode.Properties
            if (-not $oProps) { continue }

            $sActionCode = $oProps.action
            $sAction = if ($hActionCode.ContainsKey($sActionCode)) { $hActionCode[$sActionCode] } else { $sActionCode }

            $sGroupSid  = $oProps.groupSid
            $sGroupName = if ($oProps.groupName) { $oProps.groupName } else { $oGroupNode.name }

            $bDelUsers  = ($oProps.deleteAllUsers  -eq '1')
            $bDelGroups = ($oProps.deleteAllGroups -eq '1')
            $bRemoveOthers = ($sAction -eq 'Replace') -or $bDelUsers -or $bDelGroups

            $aMembers = @()
            if ($oProps.Members -and $oProps.Members.Member) {
                foreach ($oMember in @($oProps.Members.Member)) {
                    $sMAction = switch ($oMember.action) {
                        'ADD'    { 'Add' }
                        'REMOVE' { 'Remove' }
                        default  { $oMember.action }
                    }
                    $aMembers += [PSCustomObject][ordered]@{
                        Name   = $oMember.name
                        Sid    = $oMember.sid
                        Action = $sMAction
                    }
                }
            }

            [PSCustomObject][ordered]@{
                Source             = 'GPP'
                GroupSid           = $sGroupSid
                GroupName          = $sGroupName
                ResolvedName       = Resolve-ADSidName -Sid $sGroupSid
                Action             = $sAction
                NewName            = if ($oProps.newName) { $oProps.newName } else { $null }
                Description        = if ($oProps.description) { $oProps.description } else { $null }
                DeleteAllUsers     = $bDelUsers
                DeleteAllGroups    = $bDelGroups
                RemoveOtherMembers = $bRemoveOthers
                Members            = $aMembers
                ParentGroups       = @()
            }
        }
    }
}
