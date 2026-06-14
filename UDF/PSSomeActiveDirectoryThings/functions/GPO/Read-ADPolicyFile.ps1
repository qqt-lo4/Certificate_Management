function Read-ADPolicyFile {
    <#
    .SYNOPSIS
        Reads a Group Policy SYSVOL file, optionally via a PSSession.

    .DESCRIPTION
        Centralizes the file-read operation used by every GPO parser in this
        module (GptTmpl.inf, registry.pol, Groups.xml). When a -Session is
        supplied, the Test-Path and read happen inside that session via
        Invoke-Command so the file is touched by the remote machine's
        identity - useful when the GPO ACL filters out the local caller but
        a server with admin-equivalent rights can still read it.

        Returns $null when the file does not exist, regardless of mode, so
        the callers can `if (-not $content) { return }` cheaply without a
        separate Test-Path round trip.

    .PARAMETER Path
        Full UNC path to the policy file (e.g. GPCFileSysPath + relative
        sub-path).

    .PARAMETER Mode
        Read mode:
        - Text    : Get-Content -Encoding Unicode, returns an array of lines.
                    Used for GptTmpl.inf (INF format, Unicode-encoded).
        - TextRaw : Get-Content -Raw, returns a single string. Used for
                    Groups.xml (loaded as one blob then cast to [xml] by
                    the caller).
        - Bytes   : [System.IO.File]::ReadAllBytes, returns a byte[]. Used
                    for registry.pol (PReg binary format). The remote
                    scriptblock uses the comma operator to keep the byte[]
                    intact through the PSRemoting pipeline; without it
                    PowerShell would unroll the byte[] into thousands of
                    individual byte emissions.

    .PARAMETER Session
        Optional PSSession to delegate the read to. When omitted, the read
        happens locally (legacy behaviour).

    .OUTPUTS
        - Mode Text    : [string[]] | $null
        - Mode TextRaw : [string]   | $null
        - Mode Bytes   : [byte[]]   | $null

    .EXAMPLE
        $aLines = Read-ADPolicyFile -Path $sInfPath -Mode Text -Session $oSession

    .EXAMPLE
        $aBytes = Read-ADPolicyFile -Path $sRegPolPath -Mode Bytes
        if (-not $aBytes) { return }

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        1.0.0 (2026-05-19) - Initial version. Lets GPO parsers transparently
                             switch between local UNC reads and PSRemoting
                             reads via the -Session parameter, without
                             duplicating the I/O logic in each function.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$Path,

        [ValidateSet('Text', 'TextRaw', 'Bytes')]
        [string]$Mode = 'Text',

        [AllowNull()]
        [System.Management.Automation.Runspaces.PSSession]$Session
    )

    $sb = {
        Param([string]$P, [string]$M)
        if (-not (Test-Path -LiteralPath $P -ErrorAction SilentlyContinue)) { return $null }
        switch ($M) {
            'Text'    { Get-Content -LiteralPath $P -Encoding Unicode -ErrorAction Stop }
            'TextRaw' { Get-Content -LiteralPath $P -Raw -ErrorAction Stop }
            'Bytes'   { , [System.IO.File]::ReadAllBytes($P) }
        }
    }

    if ($Session) {
        Invoke-Command -Session $Session -ScriptBlock $sb -ArgumentList $Path, $Mode
    } else {
        & $sb $Path $Mode
    }
}
