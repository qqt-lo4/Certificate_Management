function Find-ADObject {
    <#
    .SYNOPSIS
        Interactive CLI dialog for finding AD objects

    .DESCRIPTION
        Provides an interactive search dialog for Active Directory objects with
        pagination, multi-select, and confirmation support. Supports filtering
        by object type (Computer, User, OU, Group, Contact, etc.).

    .PARAMETER HeaderString
        The header text displayed in the dialog. Defaults to "Please find an AD Object".

    .PARAMETER StarForbidden
        If specified, prevents using wildcard-only searches.

    .PARAMETER InputString
        Pre-filled search string.

    .PARAMETER SeparatorColor
        Color for the dialog separator lines. Defaults to Blue.

    .PARAMETER SelectedColumns
        Custom column definitions for the results display.

    .PARAMETER ItemsPerPage
        Number of items per page. Defaults to 10.

    .PARAMETER Sort
        Property to sort results by. Defaults to "name".

    .PARAMETER Computer
        Filter results to computer objects only.

    .PARAMETER User
        Filter results to user objects only.

    .PARAMETER OU
        Filter results to organizational units only.

    .PARAMETER Container
        Filter results to container objects only.

    .PARAMETER Volume
        Filter results to volume objects only.

    .PARAMETER Group
        Filter results to group objects only.

    .PARAMETER Contact
        Filter results to contact objects only.

    .PARAMETER MultiSelect
        Allow selecting multiple objects.

    .PARAMETER Confirm
        Show a confirmation dialog after selection.

    .PARAMETER ConfirmMessage
        Custom confirmation message text.

    .PARAMETER YesButtonText
        Custom text for the Yes button.

    .PARAMETER NoButtonText
        Custom text for the No button.

    .PARAMETER CancelButtonText
        Custom text for the Cancel button.

    .OUTPUTS
        The selected AD object(s).

    .EXAMPLE
        Find-ADObject -User -HeaderString "Select a user"

    .EXAMPLE
        Find-ADObject -Computer -MultiSelect -Confirm

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [string]$HeaderString = "Please find an AD Object",
        [switch]$StarForbidden,
        [string]$InputString,
        [System.ConsoleColor]$SeparatorColor = ([System.ConsoleColor]::Blue),
        [object[]]$SelectedColumns,
        [int]$ItemsPerPage = 10,
        [string]$Sort = "name",
        [switch]$Computer,
        [switch]$User,
        [switch]$OU,
        [switch]$Container,
        [switch]$Volume,
        [switch]$Group,
        [switch]$Contact,
        [switch]$MultiSelect,
        [switch]$Confirm,
        [string]$ConfirmMessage,
        [string]$YesButtonText,
        [string]$NoButtonText,
        [string]$CancelButtonText
    )
    $fFindADObject = {
        Param(
            [Parameter(Mandatory, Position = 0)]
            [string]$InputString,
            [switch]$Computer,
            [switch]$User,
            [switch]$OU,
            [switch]$Container,
            [switch]$Volume,
            [switch]$Group,
            [switch]$Contact
        )
        $aResult = @()
        $aResult += Get-ADObject -Identity $InputString -Computer:$Computer -User:$User -OU:$OU `
                                                        -Container:$Container -Volume:$Volume -Group:$Group
        return $aResult
    }
    $aDefaultParameters = @(
        "HeaderString"
        "StarForbidden"
        "InputString"
        "SeparatorColor"
        "SelectedColumns"
        "ItemsPerPage"
        "Sort"
        "MultiSelect"
        "Confirm"
        "ConfirmMessage"
        "YesButtonText"
        "NoButtonText"
        "CancelButtonText"
    )
    $hFindParameters = Copy-Hashtable -InputObject (Get-FunctionParameters) -Properties $aDefaultParameters
    foreach ($item in $aDefaultParameters) {
        $PSBoundParameters.Remove($item) | Out-Null
    }
    if ($null -eq $SelectedColumns) {
        $aSelectedColumns = @()
        $aSelectedColumns += @{l = "Name"; e = {$_.name}}
        if (-not ($Computer -xor $User -xor $OU -xor $Container -xor $Volume -xor $Group)) {
            $aSelectedColumns += @{l = "Type";     e = {$_.objectclass}}
        }
        $aSelectedColumns += @{l = "Domain" ;      e = {ConvertFrom-DN $_.distinguishedname}}
        $aSelectedColumns += @{l = "Description" ; e = {$_.description} ; AutoWidth = $true}
        $hFindParameters.SelectedColumns = $aSelectedColumns
    }
    if ($PSBoundParameters.Keys.Count -gt 0) {
        Find-Object @hFindParameters -SearchFunction $fFindADObject -SearchFunctionParameters $PSBoundParameters -SelectedObjectsUniqueProperty "adspath"
    } else {
        Find-Object @hFindParameters -SearchFunction $fFindADObject -SelectedObjectsUniqueProperty "adspath"
    }
}
