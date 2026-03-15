function Get-ADObjectDirectReports {
    <#
    .SYNOPSIS
        Retrieves the direct reports of an AD object

    .DESCRIPTION
        Returns the AD objects listed in the directReports attribute
        of the specified AD object (typically a manager).

    .PARAMETER ADObject
        The AD object to get direct reports for.

    .OUTPUTS
        Custom AD object[]. The direct reports.

    .EXAMPLE
        Get-ADObjectDirectReports -ADObject $manager

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADObject
    )
    return Get-ADObjectListProperty -ADObject $ADObject -Property "directreports"
}