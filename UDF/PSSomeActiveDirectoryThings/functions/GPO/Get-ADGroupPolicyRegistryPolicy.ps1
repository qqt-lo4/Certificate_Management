function Get-ADGroupPolicyRegistryPolicy {
    <#
    .SYNOPSIS
        Parses a GPO registry.pol file (PReg binary format).

    .DESCRIPTION
        Reads a Group Policy registry.pol file, which contains registry-based
        policy settings in Microsoft's binary "PReg" format:

            Header : "PReg" (0x50 0x52 0x65 0x67) + version DWORD (0x01000000)
            Record : '[' key '\0' ';' value '\0' ';' type(DWORD) ';' size(DWORD) ';' data ']'

        All strings are UTF-16LE, null-terminated. Brackets and semicolons are
        UTF-16LE single characters (2 bytes each).

        Returns one PSCustomObject per entry with Key, Value, Type, Data.

    .PARAMETER Path
        Path to the registry.pol file.

    .OUTPUTS
        PSCustomObject[] with properties: Key, Value, Type, Data.

    .EXAMPLE
        Get-ADGroupPolicyRegistryPolicy -Path "\\contoso.com\SYSVOL\contoso.com\Policies\{...}\USER\registry.pol"

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-04-13) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    Process {
        if (-not (Test-Path $Path)) { return }

        $aBytes = [System.IO.File]::ReadAllBytes($Path)
        if ($aBytes.Length -lt 8) { return }

        # Signature check: "PReg"
        if ($aBytes[0] -ne 0x50 -or $aBytes[1] -ne 0x52 -or `
            $aBytes[2] -ne 0x65 -or $aBytes[3] -ne 0x67) {
            Write-Warning "Not a registry.pol file: $Path"
            return
        }

        $i = 8  # Skip header (4 signature + 4 version)
        $iLen = $aBytes.Length

        # Helper: read a UTF-16LE null-terminated string starting at $i, advance $i
        function Read-Utf16String {
            Param([byte[]]$Data, [ref]$Index, [int]$Length)
            $iStart = $Index.Value
            while (($Index.Value + 1) -lt $Length -and `
                   -not ($Data[$Index.Value] -eq 0x00 -and $Data[$Index.Value + 1] -eq 0x00)) {
                $Index.Value += 2
            }
            $iBytes = $Index.Value - $iStart
            $s = if ($iBytes -gt 0) { [System.Text.Encoding]::Unicode.GetString($Data, $iStart, $iBytes) } else { "" }
            $Index.Value += 2  # consume null terminator
            return $s
        }

        while ($i -lt $iLen) {
            # Expect '[' (0x5B 0x00)
            if (($i + 1) -ge $iLen -or $aBytes[$i] -ne 0x5B -or $aBytes[$i + 1] -ne 0x00) { break }
            $i += 2

            # Key
            $iRef = [ref]$i
            $sKey = Read-Utf16String -Data $aBytes -Index $iRef -Length $iLen
            $i = $iRef.Value
            # Expect ';'
            if (($i + 1) -lt $iLen -and $aBytes[$i] -eq 0x3B -and $aBytes[$i + 1] -eq 0x00) { $i += 2 }

            # Value name
            $iRef = [ref]$i
            $sValue = Read-Utf16String -Data $aBytes -Index $iRef -Length $iLen
            $i = $iRef.Value
            if (($i + 1) -lt $iLen -and $aBytes[$i] -eq 0x3B -and $aBytes[$i + 1] -eq 0x00) { $i += 2 }

            # Type (DWORD LE)
            if (($i + 4) -gt $iLen) { break }
            $iType = [BitConverter]::ToInt32($aBytes, $i); $i += 4
            if (($i + 1) -lt $iLen -and $aBytes[$i] -eq 0x3B -and $aBytes[$i + 1] -eq 0x00) { $i += 2 }

            # Size (DWORD LE)
            if (($i + 4) -gt $iLen) { break }
            $iSize = [BitConverter]::ToInt32($aBytes, $i); $i += 4
            if (($i + 1) -lt $iLen -and $aBytes[$i] -eq 0x3B -and $aBytes[$i + 1] -eq 0x00) { $i += 2 }

            # Data
            $oData = $null
            if ($iSize -gt 0 -and ($i + $iSize) -le $iLen) {
                switch ($iType) {
                    1 { $oData = [System.Text.Encoding]::Unicode.GetString($aBytes, $i, $iSize).TrimEnd([char]0) } # REG_SZ
                    2 { $oData = [System.Text.Encoding]::Unicode.GetString($aBytes, $i, $iSize).TrimEnd([char]0) } # REG_EXPAND_SZ
                    4 { $oData = [BitConverter]::ToUInt32($aBytes, $i) }                                           # REG_DWORD
                    7 {                                                                                            # REG_MULTI_SZ
                        $sMulti = [System.Text.Encoding]::Unicode.GetString($aBytes, $i, $iSize)
                        $oData = @($sMulti.Split([char]0) | Where-Object { $_ })
                    }
                    default { $oData = $aBytes[$i..($i + $iSize - 1)] }
                }
            }
            $i += $iSize

            # Expect ']' (0x5D 0x00)
            if (($i + 1) -lt $iLen -and $aBytes[$i] -eq 0x5D -and $aBytes[$i + 1] -eq 0x00) { $i += 2 }

            $sTypeName = switch ($iType) {
                1 { 'REG_SZ' }
                2 { 'REG_EXPAND_SZ' }
                3 { 'REG_BINARY' }
                4 { 'REG_DWORD' }
                7 { 'REG_MULTI_SZ' }
                default { "($iType)" }
            }

            [PSCustomObject][ordered]@{
                Key   = $sKey
                Value = $sValue
                Type  = $sTypeName
                Data  = $oData
            }
        }
    }
}
