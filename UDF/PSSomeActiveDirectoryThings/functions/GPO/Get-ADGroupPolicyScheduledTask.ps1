function Get-ADGroupPolicyScheduledTask {
    <#
    .SYNOPSIS
        Extracts Scheduled Tasks managed by a GPO via Group Policy
        Preferences (GPP).

    .DESCRIPTION
        Reads Machine\Preferences\ScheduledTasks\ScheduledTasks.xml in
        the GPO's SYSVOL folder and returns one object per task. Four
        GPP element names are handled:

            <Task>             - XP-era scheduled task
            <ImmediateTask>    - XP-era one-shot task
            <TaskV2>           - Windows 7+ scheduled task
            <ImmediateTaskV2>  - Windows 7+ one-shot task

        Inner Win32 Task Scheduler XML (TaskV2 / ImmediateTaskV2) is
        unpacked so the principal, command, arguments, and trigger
        summary all surface as flat properties, which is what auditors
        need at a glance. Legacy Task / ImmediateTask attributes are
        read directly off the Properties element.

        Tasks that schedule security-relevant work (auditing scripts,
        SMB session inventories, patch deployments, ...) are common
        hardening artefacts and should be visible to the auditor; this
        helper surfaces them in a uniform shape regardless of GPP
        variant.

    .PARAMETER GPCFileSysPath
        UNC path to the GPO's SYSVOL folder (gPCFileSysPath attribute).

    .PARAMETER Credential
        Optional PSCredential for SYSVOL access.

    .PARAMETER Session
        Optional PSSession to read ScheduledTasks.xml through. The
        XML parse happens locally; only the file read crosses the
        wire, which lets a remote admin host bypass GPO ACLs that
        filter the local caller.

    .OUTPUTS
        PSCustomObject[] with properties:
            Variant      ('Task' | 'ImmediateTask' | 'TaskV2' | 'ImmediateTaskV2')
            Name         (display name)
            Action       ('Create' | 'Update' | 'Replace' | 'Delete')
            RunAs        (principal that runs the task, e.g. "NT AUTHORITY\System")
            RunLevel     ('HighestAvailable' | 'LeastPrivilege' | $null)
            Command      (executable / script path)
            Arguments    (command-line arguments, may be empty)
            WorkingDir   (working directory, may be empty)
            Triggers     (short text summary, e.g. "Daily 03:00; AtLogon")
            Description  (task description if any)
            Enabled      (task enabled state - boolean or $null)
            Hidden       (whether the task hides itself from the UI)
        Returns nothing if ScheduledTasks.xml is absent.

    .EXAMPLE
        Get-ADGroupPolicyScheduledTask -GPCFileSysPath $oGPO.gPCFileSysPath

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-05-26) - Initial version
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
        $sXmlPath = Join-Path $GPCFileSysPath 'Machine\Preferences\ScheduledTasks\ScheduledTasks.xml'

        # Read via Read-ADPolicyFile so -Session transparently delegates
        # to the remote host. TextRaw mode returns the file as a single
        # string suitable for [xml] cast; $null when the file is absent.
        $sXml = $null
        try {
            $sXml = Read-ADPolicyFile -Path $sXmlPath -Mode TextRaw -Session $Session
        } catch {
            Write-Warning "Get-ADGroupPolicyScheduledTask : cannot access '$sXmlPath' - $_"
            return
        }
        if (-not $sXml) { return }

        $oXml = $null
        try {
            $oXml = [xml]$sXml
        } catch {
            Write-Warning "Get-ADGroupPolicyScheduledTask : malformed XML '$sXmlPath' - $_"
            return
        }
        if (-not $oXml.ScheduledTasks) { return }

        # GPP action codes: C=Create, U=Update, R=Replace, D=Delete.
        # Anything else is passed through verbatim so changes to the
        # schema don't silently lose data.
        function Resolve-Action {
            Param([string]$Code)
            switch ($Code) {
                'C' { 'Create' }
                'U' { 'Update' }
                'R' { 'Replace' }
                'D' { 'Delete' }
                default { if ($Code) { $Code } else { $null } }
            }
        }

        # Short text summary of the inner Triggers block (TaskV2 /
        # ImmediateTaskV2). The Win32 Task Scheduler XML supports many
        # trigger types; we render each one as a one-liner and join
        # them with "; " so an auditor can glance at the schedule
        # without parsing XML mentally.
        function Format-Triggers {
            Param($Triggers)
            if (-not $Triggers) { return '' }
            $aOut = @()
            foreach ($oT in $Triggers.ChildNodes) {
                switch ($oT.LocalName) {
                    'TimeTrigger'      {
                        $sBoundary = if ($oT.StartBoundary) { $oT.StartBoundary } else { '?' }
                        $aOut += "OneTime $sBoundary"
                    }
                    'CalendarTrigger'  {
                        $sBoundary = if ($oT.StartBoundary) { $oT.StartBoundary } else { '?' }
                        $sFreq = if     ($oT.ScheduleByDay)     { 'Daily' }
                                 elseif ($oT.ScheduleByWeek)    { 'Weekly' }
                                 elseif ($oT.ScheduleByMonth)   { 'Monthly' }
                                 elseif ($oT.ScheduleByMonthDayOfWeek) { 'MonthlyDOW' }
                                 else                           { 'Calendar' }
                        $aOut += "$sFreq $sBoundary"
                    }
                    'LogonTrigger'     { $aOut += 'AtLogon' }
                    'BootTrigger'      { $aOut += 'AtBoot' }
                    'IdleTrigger'      { $aOut += 'WhenIdle' }
                    'EventTrigger'     { $aOut += 'OnEvent' }
                    'RegistrationTrigger' { $aOut += 'AtRegistration' }
                    'SessionStateChangeTrigger' { $aOut += 'OnSessionChange' }
                    default            { if ($oT.LocalName) { $aOut += $oT.LocalName } }
                }
            }
            return ($aOut -join '; ')
        }

        # --- Modern variants (TaskV2 / ImmediateTaskV2) ------------------
        # Inner Task element follows the Win32 Task Scheduler XML schema,
        # so principal + actions + triggers all live as children of
        # Properties/Task. UserId and RunLevel come from the first
        # Principal; Exec is the first Action child (Send-EmailV2,
        # ShowMessage etc. are rare in hardening contexts and intentionally
        # ignored - they wouldn't be Command/Arguments anyway).
        foreach ($sVariant in @('TaskV2', 'ImmediateTaskV2')) {
            $aTasks = @($oXml.ScheduledTasks.SelectNodes("//$sVariant"))
            foreach ($oTask in $aTasks) {
                $oProps = $oTask.Properties
                if (-not $oProps) { continue }
                $oInner = $oProps.Task

                $sUser = $null; $sRunLevel = $null
                if ($oInner -and $oInner.Principals -and $oInner.Principals.Principal) {
                    $oP = @($oInner.Principals.Principal)[0]
                    $sUser     = $oP.UserId
                    $sRunLevel = $oP.RunLevel
                }
                $sCmd = $null; $sArgs = $null; $sWD = $null
                if ($oInner -and $oInner.Actions -and $oInner.Actions.Exec) {
                    $oExec = @($oInner.Actions.Exec)[0]
                    $sCmd  = $oExec.Command
                    $sArgs = $oExec.Arguments
                    $sWD   = $oExec.WorkingDirectory
                }
                $sTriggers = ''
                if ($oInner -and $oInner.Triggers) {
                    $sTriggers = Format-Triggers $oInner.Triggers
                }
                $sDesc = $null
                if ($oInner -and $oInner.RegistrationInfo) {
                    $sDesc = $oInner.RegistrationInfo.Description
                }
                $bEnabled = $null
                if ($oInner -and $oInner.Settings -and ($null -ne $oInner.Settings.Enabled)) {
                    $bEnabled = [string]::Equals($oInner.Settings.Enabled, 'true', 'OrdinalIgnoreCase')
                }
                $bHidden = $null
                if ($oInner -and $oInner.Settings -and ($null -ne $oInner.Settings.Hidden)) {
                    $bHidden = [string]::Equals($oInner.Settings.Hidden, 'true', 'OrdinalIgnoreCase')
                }

                [PSCustomObject][ordered]@{
                    Variant     = $sVariant
                    Name        = $oTask.name
                    Action      = Resolve-Action $oProps.action
                    RunAs       = $sUser
                    RunLevel    = $sRunLevel
                    Command     = $sCmd
                    Arguments   = $sArgs
                    WorkingDir  = $sWD
                    Triggers    = $sTriggers
                    Description = $sDesc
                    Enabled     = $bEnabled
                    Hidden      = $bHidden
                }
            }
        }

        # --- Legacy variants (Task / ImmediateTask) ----------------------
        # XP-era schema where most properties live as attributes directly
        # on Properties (no inner Win32 Task XML). Triggers come as a
        # collection of <Triggers><Trigger type=".."/></Triggers> with
        # type codes 1..7 — collapsed into the same one-liner format.
        foreach ($sVariant in @('Task', 'ImmediateTask')) {
            $aTasks = @($oXml.ScheduledTasks.SelectNodes("//$sVariant"))
            foreach ($oTask in $aTasks) {
                $oProps = $oTask.Properties
                if (-not $oProps) { continue }

                # Triggers in legacy form: <Triggers><Trigger type="N">...
                $aTrigText = @()
                if ($oProps.Triggers -and $oProps.Triggers.Trigger) {
                    foreach ($oT in @($oProps.Triggers.Trigger)) {
                        $sLabel = switch ($oT.type) {
                            '1' { 'Daily' }
                            '2' { 'Weekly' }
                            '3' { 'Monthly' }
                            '4' { 'MonthlyDOW' }
                            '5' { 'OneTime' }
                            '6' { 'AtBoot' }
                            '7' { 'AtLogon' }
                            default { "Type$($oT.type)" }
                        }
                        $sWhen = if ($oT.beginDate -or $oT.startTime) {
                            ("$($oT.beginDate) $($oT.startTime)").Trim()
                        } else { '' }
                        $aTrigText += ("$sLabel $sWhen").Trim()
                    }
                }

                [PSCustomObject][ordered]@{
                    Variant     = $sVariant
                    Name        = $oTask.name
                    Action      = Resolve-Action $oProps.action
                    RunAs       = $oProps.runAs
                    RunLevel    = $null
                    Command     = $oProps.appName
                    Arguments   = $oProps.args
                    WorkingDir  = $oProps.startIn
                    Triggers    = ($aTrigText -join '; ')
                    Description = $oProps.comment
                    Enabled     = if ($null -ne $oProps.enabled) {
                                      [string]::Equals($oProps.enabled, '1', 'OrdinalIgnoreCase') -or `
                                      [string]::Equals($oProps.enabled, 'true', 'OrdinalIgnoreCase')
                                  } else { $null }
                    Hidden      = $null
                }
            }
        }
    }
}
