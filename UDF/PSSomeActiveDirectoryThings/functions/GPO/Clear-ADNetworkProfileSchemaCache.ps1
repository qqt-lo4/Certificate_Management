function Clear-ADNetworkProfileSchemaCache {
    <#
    .SYNOPSIS
        Drops every entry from the schema-availability cache used by
        Get-ADGroupPolicyNetworkProfile.

    .DESCRIPTION
        Resets $global:ADNetworkProfileSchema. Call this when the
        schema state on a target server may have changed since the
        last probe (e.g., a wireless policy schema extension was
        applied mid-session) and you want subsequent
        Get-ADGroupPolicyNetworkProfile calls to re-probe.

        The cache is global rather than module-scoped on purpose - it
        survives Import-Module -Force during iterative development.

    .EXAMPLE
        Clear-ADNetworkProfileSchemaCache

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-05-28) - Initial version. Companion to
                             Get-ADGroupPolicyNetworkProfile.
    #>
    [CmdletBinding()]
    Param()

    Process {
        $global:ADNetworkProfileSchema = @{}
    }
}
