function Clear-ADSidNameCache {
    <#
    .SYNOPSIS
        Drops every entry from the SID->NTAccount cache used by
        Resolve-ADSidName.

    .DESCRIPTION
        Resets $global:ADSidNameCache. Useful when a long-running session
        has accumulated entries that may no longer be valid (e.g., a SID
        was re-created with a different name in the directory) or before
        a fresh batch when you want unambiguous timing for SID resolution
        work.

        The cache is global rather than module-scoped on purpose - it
        survives Import-Module -Force during iterative development. Call
        this function explicitly to wipe it.

    .EXAMPLE
        Clear-ADSidNameCache

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-05-26) - Initial version. Companion to Resolve-ADSidName.
    #>
    [CmdletBinding()]
    Param()

    Process {
        $global:ADSidNameCache = @{}
    }
}
