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
        [PSCredential]$Credential
    )

    Process {
        $sInfPath = Join-Path $GPCFileSysPath "MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

        # Probe + read the INF file in a single guarded block so that any
        # SYSVOL access failure (permission denied, network issues, ...) is
        # surfaced once with the offending path and the function exits
        # gracefully — the caller (and the overall export) keeps running.
        $aLines = $null
        try {
            if (-not (Test-Path $sInfPath -ErrorAction Stop)) {
                # Not all GPOs contain a security template (only those defining
                # password / lockout / audit / privilege / registry security
                # settings do). Treat missing files as "no settings" silently.
                Write-Verbose "GptTmpl.inf not found: $sInfPath"
                return
            }
            $aLines = Get-Content -Path $sInfPath -Encoding Unicode -ErrorAction Stop
        } catch {
            Write-Warning "Get-ADGroupPolicySecuritySettings : cannot access '$sInfPath' - $_"
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
