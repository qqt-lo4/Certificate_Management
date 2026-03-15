function Get-ADObjectMemberOf {
    <#
    .SYNOPSIS
        Retrieves the group memberships of an AD object

    .DESCRIPTION
        Returns the groups that the specified AD object is a member of
        by reading its memberOf attribute.

    .PARAMETER ADObject
        The AD object to get group memberships for.

    .OUTPUTS
        Custom AD object[]. The groups the object belongs to.

    .EXAMPLE
        Get-ADObjectMemberOf -ADObject $user

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADObject
    )
    return Get-ADObjectListProperty -ADObject $ADObject -Property "memberof"
}
