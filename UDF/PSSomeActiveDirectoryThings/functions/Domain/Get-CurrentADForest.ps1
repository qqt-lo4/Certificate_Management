function Get-CurrentADForest {
    <#
    .SYNOPSIS
        Returns the current Active Directory forest

    .DESCRIPTION
        Retrieves the AD forest object for the current user's context using
        System.DirectoryServices.ActiveDirectory.Forest.

    .OUTPUTS
        System.DirectoryServices.ActiveDirectory.Forest. The current AD forest.

    .EXAMPLE
        $forest = Get-CurrentADForest

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
}