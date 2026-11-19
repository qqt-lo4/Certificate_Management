function Get-DerChildren {
    <#
    .SYNOPSIS
        Reads the immediate child elements of a constructed DER element.

    .PARAMETER Data
        DER byte array containing the parent and its children.

    .PARAMETER Parent
        Element returned by Read-DerElement.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [byte[]]$Data,
        [Parameter(Mandatory)]
        [object]$Parent
    )
    $aChildren = [System.Collections.Generic.List[object]]::new()
    $iPosition = $Parent.ContentStart
    while ($iPosition -lt $Parent.End) {
        $oChild = Read-DerElement -Data $Data -Offset $iPosition
        $aChildren.Add($oChild)
        $iPosition = $oChild.End
    }
    if ($iPosition -ne $Parent.End) { throw 'Malformed DER constructed element.' }
    return $aChildren.ToArray()
}