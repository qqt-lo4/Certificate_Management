function Get-ADGroupPolicyLAPSSettings {
    <#
    .SYNOPSIS
        Extracts LAPS configuration parameters defined by a GPO.

    .DESCRIPTION
        Parses Machine\registry.pol from a GPO's SYSVOL folder and returns
        the registry entries that configure LAPS. Recognises both LAPS
        deployment generations:

        - Legacy LAPS (Microsoft LAPS, ms-Mcs-AdmPwd attribute) :
          HKLM\Software\Policies\Microsoft Services\AdmPwd
          (note: "Microsoft Services" is a single registry key name
           that contains a space — not two nested keys)

        - Windows LAPS (built into Windows 10 22H2+, Windows 11, Server 2019+) :
          HKLM\Software\Microsoft\Policies\LAPS or
          HKLM\Software\Policies\Microsoft\Windows\LAPS

        Returns one PSCustomObject per LAPS-related registry value with the
        same shape as Get-ADGroupPolicyRegistryPolicy plus a Source label
        ('Legacy LAPS' or 'Windows LAPS') and a DisplayValue column with a
        human-readable rendering of the raw data (complexity flag, backup
        directory mode, post-authentication action, boolean toggles, etc.).

    .PARAMETER GPCFileSysPath
        UNC path to the GPO's SYSVOL folder (gPCFileSysPath attribute).

    .PARAMETER Credential
        Optional PSCredential for SYSVOL access. Reserved for future use.
        registry.pol is currently read with the calling thread's identity.

    .OUTPUTS
        PSCustomObject[] with properties: Source, Key, Value, Type, Data, DisplayValue.
        Returns nothing if Machine\registry.pol does not exist or the GPO
        does not contain LAPS-related entries.

    .EXAMPLE
        Get-ADGroupPolicy -Identity "LAPS Deployment" -Properties gPCFileSysPath |
            ForEach-Object { Get-ADGroupPolicyLAPSSettings -GPCFileSysPath $_.gPCFileSysPath }

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
        $sPolPath = Join-Path $GPCFileSysPath 'Machine\registry.pol'

        # The local Test-Path that used to live here was redundant - and a
        # silent bug when -Session is set (it'd run on the local host and
        # short-circuit even when the remote DC could read the file).
        # Get-ADGroupPolicyRegistryPolicy already returns nothing on a
        # missing or unreadable file, so we just call it directly.
        $aEntries = @()
        try {
            $hRegParams = @{ Path = $sPolPath }
            if ($Session) { $hRegParams['Session'] = $Session }
            $aEntries = @(Get-ADGroupPolicyRegistryPolicy @hRegParams)
        } catch {
            Write-Warning "Get-ADGroupPolicyLAPSSettings : cannot parse '$sPolPath' - $_"
            return
        }
        if ($aEntries.Count -eq 0) { return }

        # Map of LAPS registry key prefixes to source labels. Order matters:
        # the first match wins (Legacy is checked first to keep its label
        # distinct from Windows LAPS).
        $hSources = [ordered]@{
            'Software\Policies\Microsoft Services\AdmPwd' = 'Legacy LAPS'
            'Software\Microsoft\Policies\LAPS'            = 'Windows LAPS'
            'Software\Policies\Microsoft\Windows\LAPS'    = 'Windows LAPS'
        }

        # --- Helper: human-readable transform for known LAPS values ---------
        function Format-LAPSDisplay {
            Param([string]$Value, [object]$Data)

            # Boolean toggles (DWORD 0/1)
            $aBoolKeys = @(
                'AdmPwdEnabled'                  # Legacy LAPS
                'PwdExpirationProtectionEnabled' # Legacy LAPS
                'EncryptionEnabled'              # Windows LAPS (deprecated name)
                'ADPasswordEncryptionEnabled'    # Windows LAPS
            )
            if ($Value -in $aBoolKeys) {
                switch ([int]$Data) {
                    0       { return '0 - Disabled' }
                    1       { return '1 - Enabled' }
                    default { return "$Data" }
                }
            }

            switch ($Value) {
                'PasswordComplexity' {
                    switch ([int]$Data) {
                        1       { return '1 - Large letters' }
                        2       { return '2 - Large + small letters' }
                        3       { return '3 - Large + small letters + numbers' }
                        4       { return '4 - Large + small + numbers + special' }
                        default { return "$Data" }
                    }
                }
                'BackupDirectory' {
                    # Windows LAPS only
                    switch ([int]$Data) {
                        0       { return '0 - Disabled' }
                        1       { return '1 - Azure Active Directory' }
                        2       { return '2 - Active Directory' }
                        default { return "$Data" }
                    }
                }
                'PostAuthenticationActions' {
                    # Windows LAPS — bitmask, but documented values are 1, 3, 5
                    switch ([int]$Data) {
                        1       { return '1 - Reset password' }
                        3       { return '3 - Reset password + sign out' }
                        5       { return '5 - Reset password + reboot' }
                        default { return "$Data" }
                    }
                }
                'PasswordAgeDays' {
                    return "$Data day(s)"
                }
                'PasswordLength' {
                    return "$Data character(s)"
                }
                'PasswordHistoryLength' {
                    return "$Data password(s) remembered"
                }
                'PostAuthenticationResetDelay' {
                    if ([int]$Data -eq 0) { return '0 - Disabled' }
                    return "$Data hour(s)"
                }
                default {
                    return "$Data"
                }
            }
        }

        foreach ($oEntry in $aEntries) {
            $sSource = $null
            foreach ($sPrefix in $hSources.Keys) {
                if ($oEntry.Key -like "$sPrefix*") {
                    $sSource = $hSources[$sPrefix]
                    break
                }
            }
            if (-not $sSource) { continue }

            [PSCustomObject][ordered]@{
                Source       = $sSource
                Key          = $oEntry.Key
                Value        = $oEntry.Value
                Type         = $oEntry.Type
                Data         = $oEntry.Data
                DisplayValue = Format-LAPSDisplay -Value $oEntry.Value -Data $oEntry.Data
            }
        }
    }
}
