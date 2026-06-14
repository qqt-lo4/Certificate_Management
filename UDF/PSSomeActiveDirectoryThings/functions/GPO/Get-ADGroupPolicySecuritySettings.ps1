function Get-ADGroupPolicySecuritySettings {
    <#
    .SYNOPSIS
        Reads the security settings (GptTmpl.inf) from a GPO's SYSVOL path.

    .DESCRIPTION
        Parses the Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf file
        located in the GPO's SYSVOL folder. This INF file contains the
        security template with sections such as:

        - [System Access]    : Password and account lockout policy
        - [Kerberos Policy]  : Kerberos ticket settings
        - [Event Audit]      : Audit policy settings
        - [Privilege Rights]  : User rights assignments
        - [Registry Values]  : Registry-based security settings

        Returns one PSCustomObject per setting with its section, key, and value.

    .PARAMETER GPCFileSysPath
        The UNC path to the GPO folder in SYSVOL (gPCFileSysPath attribute).
        Accepts pipeline input from Get-ADGroupPolicy objects.

    .PARAMETER Credential
        Optional PSCredential for SYSVOL access.

    .PARAMETER Session
        Optional PSSession to read the file from. When set, the SYSVOL
        Test-Path / Get-Content runs inside the session via Invoke-Command,
        so the file is touched by the remote machine's identity. Useful
        when the GPO ACL filters out the local caller but a remote admin
        host can still read it.

    .OUTPUTS
        PSCustomObject[] with properties: Section, Setting, Type, Value.
        Type is populated only for [Registry Values] entries (REG_SZ,
        REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_MULTI_SZ); for other
        sections it is $null.
        Returns nothing if GptTmpl.inf does not exist.

    .EXAMPLE
        Get-ADGroupPolicySecuritySettings -GPCFileSysPath "\\contoso.com\SYSVOL\contoso.com\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}"

    .EXAMPLE
        Get-ADGroupPolicy -Identity "Default Domain Policy" -Properties gPCFileSysPath |
            ForEach-Object { Get-ADGroupPolicySecuritySettings -GPCFileSysPath $_.gPCFileSysPath }

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        1.0.0 (2026-04-12) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)]
        [string]$GPCFileSysPath,

        [AllowNull()]
        [PSCredential]$Credential,

        [AllowNull()]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    Process {
        $sInfPath = Join-Path $GPCFileSysPath "MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

        # Read via Read-ADPolicyFile so the lookup transparently delegates to a
        # PSSession when -Session is set. The helper returns $null when the file
        # is absent (Test-Path failure inside the read scriptblock), so we don't
        # need a separate Test-Path round trip - particularly important when the
        # file is on a remote SYSVOL the local caller cannot reach.
        $aLines = $null
        try {
            $aLines = Read-ADPolicyFile -Path $sInfPath -Mode Text -Session $Session
        } catch {
            Write-Warning "Get-ADGroupPolicySecuritySettings : cannot access '$sInfPath' - $_"
            return
        }
        if ($null -eq $aLines) {
            # Not all GPOs contain a security template (only those defining
            # password / lockout / audit / privilege / registry security
            # settings do). Treat missing files as "no settings" silently.
            Write-Verbose "GptTmpl.inf not found: $sInfPath"
            return
        }

        # Registry type codes used by [Registry Values] entries.
        # Format in GptTmpl.inf: "fullKeyPath=type,data"
        $hRegTypeNames = @{
            '1' = 'REG_SZ'; '2' = 'REG_EXPAND_SZ'; '3' = 'REG_BINARY'
            '4' = 'REG_DWORD'; '7' = 'REG_MULTI_SZ'
        }

        $sCurrentSection = $null

        foreach ($sLine in $aLines) {
            $sLine = $sLine.Trim()

            # Skip empty lines and comments
            if (-not $sLine -or $sLine.StartsWith(';')) { continue }

            # Section header
            if ($sLine -match '^\[(.+)\]$') {
                $sCurrentSection = $Matches[1]
                continue
            }

            # Skip signature/version metadata
            if ($sCurrentSection -eq 'Unicode' -or $sCurrentSection -eq 'Version') { continue }

            # Key = Value pairs
            if ($sCurrentSection -and $sLine -match '^(.+?)\s*=\s*(.*)$') {
                $sKey = $Matches[1].Trim()
                $sValue = $Matches[2].Trim()
                $sType = 'INI section'

                # [Registry Values] stores "type,data" — split into Type / Value
                if ($sCurrentSection -eq 'Registry Values' -and $sValue -match '^(\d+),(.*)$') {
                    $sType = if ($hRegTypeNames[$Matches[1]]) { $hRegTypeNames[$Matches[1]] } else { "($($Matches[1]))" }
                    $sValue = $Matches[2]
                }

                [PSCustomObject][ordered]@{
                    Section = $sCurrentSection
                    Setting = $sKey
                    Type    = $sType
                    Value   = $sValue
                }
            }
        }
    }
}
