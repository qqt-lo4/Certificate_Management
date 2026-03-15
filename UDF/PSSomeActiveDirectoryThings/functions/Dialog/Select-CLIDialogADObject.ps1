function Select-CLIDialogADObject {
    <#
    .SYNOPSIS
        Interactive CLI dialog for selecting an AD object

    .DESCRIPTION
        Provides a complete interactive workflow for selecting an AD object: prompts
        for input, searches AD, displays paginated results, and lets the user select
        an object. Supports filtering by type, custom properties, and navigation actions.

    .PARAMETER InputString
        Pre-filled search input string.

    .PARAMETER Identity
        Direct AD object identity (DN, GUID, etc.) to look up.

    .PARAMETER Server
        AD server to query when using Identity.

    .PARAMETER Properties
        Additional AD properties to load on the selected object.

    .PARAMETER AllowEmpty
        Allow empty input without error.

    .PARAMETER ValueIfEmpty
        Value to return when input is empty.

    .PARAMETER Computer
        Filter to computer objects.

    .PARAMETER User
        Filter to user objects.

    .PARAMETER OU
        Filter to organizational units.

    .PARAMETER Container
        Filter to container objects.

    .PARAMETER Volume
        Filter to volume objects.

    .PARAMETER Group
        Filter to group objects.

    .PARAMETER ReturnDN
        If specified, returns only the distinguished name instead of the full object.

    .PARAMETER HeaderQuestion
        The prompt text shown to the user.

    .PARAMETER NoObjectsMatchingQuery
        Message shown when no results are found.

    .PARAMETER ItemsPerPage
        Number of results per page. Defaults to 10.

    .PARAMETER OtherMenuItems
        Additional menu items (Back, Exit buttons).

    .PARAMETER SeparatorColor
        Color for the dialog separators.

    .PARAMETER HeaderTextInSeparator
        If specified, places header text within separator lines.

    .OUTPUTS
        The selected AD object, its DN, or a dialog action result.

    .EXAMPLE
        $user = Select-CLIDialogADObject -User -HeaderQuestion "Select a user"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    [CmdletBinding(DefaultParameterSetName = "Default")]
    Param(
        [Parameter(ParameterSetName = "InputString")]
        [string]$InputString,

        [Parameter(ParameterSetName = "Identity")]
        [string]$Identity,

        [Parameter(ParameterSetName = "Identity")]
        [string]$Server,

        [Parameter(ParameterSetName = "Default")]
        [Parameter(ParameterSetName = "InputString")]
        [Parameter(ParameterSetName = "Identity")]
        [string[]]$Properties,

        [Parameter(ParameterSetName = "Default")]
        [Parameter(ParameterSetName = "InputString")]
        [Parameter(ParameterSetName = "Identity")]
        [switch]$AllowEmpty,

        [Parameter(ParameterSetName = "Default")]
        [Parameter(ParameterSetName = "InputString")]
        [Parameter(ParameterSetName = "Identity")]
        [object]$ValueIfEmpty,

        [Parameter(ParameterSetName = "Default")]
        [Parameter(ParameterSetName = "InputString")]
        [Parameter(ParameterSetName = "Identity")]
        [switch]$Computer,

        [Parameter(ParameterSetName = "Default")]
        [Parameter(ParameterSetName = "InputString")]
        [Parameter(ParameterSetName = "Identity")]
        [switch]$User,

        [Parameter(ParameterSetName = "Default")]
        [Parameter(ParameterSetName = "InputString")]
        [Parameter(ParameterSetName = "Identity")]
        [switch]$OU,

        [Parameter(ParameterSetName = "Default")]
        [Parameter(ParameterSetName = "InputString")]
        [Parameter(ParameterSetName = "Identity")]
        [switch]$Container,

        [Parameter(ParameterSetName = "Default")]
        [Parameter(ParameterSetName = "InputString")]
        [Parameter(ParameterSetName = "Identity")]
        [switch]$Volume,

        [Parameter(ParameterSetName = "Default")]
        [Parameter(ParameterSetName = "InputString")]
        [Parameter(ParameterSetName = "Identity")]
        [switch]$Group,

        [Parameter(ParameterSetName = "Default")]
        [Parameter(ParameterSetName = "InputString")]
        [Parameter(ParameterSetName = "Identity")]
        [switch]$ReturnDN,

        [Parameter(ParameterSetName = "Default")]
        [Parameter(ParameterSetName = "InputString")]
        [Parameter(ParameterSetName = "Identity")]
        [string]$HeaderQuestion = "Please enter computer or username",

        [Parameter(ParameterSetName = "Default")]
        [Parameter(ParameterSetName = "InputString")]
        [Parameter(ParameterSetName = "Identity")]
        [AllowEmptyString()]
        [string]$NoObjectsMatchingQuery = "No objects matching query",

        [Parameter(ParameterSetName = "Default")]
        [Parameter(ParameterSetName = "InputString")]
        [Parameter(ParameterSetName = "Identity")]
        [int]$ItemsPerPage = 10,

        [Parameter(ParameterSetName = "Default")]
        [Parameter(ParameterSetName = "InputString")]
        [Parameter(ParameterSetName = "Identity")]
        [object]$OtherMenuItems = (New-CLIDialogObjectsRow -Header "Go to" -Row @(
            New-CLIDialogButton -Text "Back" -Underline 0 -Keyboard B -Back
            New-CLIDialogButton -Text "Exit" -Underline 0 -Keyboard E -Exit
        )),

        [System.ConsoleColor]$SeparatorColor = (Get-Host).UI.RawUI.ForegroundColor,
        [switch]$HeaderTextInSeparator
    )
    Begin {
        function ConvertFrom-DN {
            Param(
                [Parameter(Mandatory, Position = 0)]
                [ValidatePattern("((DC|dc)=)(?<name>[A-Za-z._0-9-]+)")]
                [string]$DN
            )
            $oMatchInfo = $DN | Select-String -Pattern "((DC|dc)=)(?<name>[A-Za-z._0-9-]+)" -AllMatches
            $sResult = (($oMatchInfo.Matches.Groups | Where-Object { $_.Name -eq "name" }).Value) -join "."
            return $sResult
        }
    }
    Process {
        $hQuery = if ($PSCmdlet.ParameterSetName -eq "Identity") {
            $hGetADOArgs = @{
                Identity = $Identity
            }
            if ($Server) {
                $hGetADOArgs.Server = $Server
            }
            $hGetADOArgs
        } else {
            $hReadADOIdentityArgs = @{
                HeaderQuestion = $HeaderQuestion
            }
            if ($InputString) {$hReadADOIdentityArgs.InputString = $InputString}
    
            $oReadADOIdentity = Read-ADObjectIdentity @hReadADOIdentityArgs
            if (($InputString) -and ($oReadADOIdentity -eq $null)) {
                throw [System.ArgumentException] "Input is not a recognized format"
            }
            $oReadADOIdentity.Remove("Type")
            $oReadADOIdentity.Remove("RegexType")
            $oReadADOIdentity.Remove("Details")
            $oReadADOIdentity.Remove("Category")
            $oReadADOIdentity
        }
        $aADObjects = Get-ADObject @hQuery -Computer:$Computer -User:$User -OU:$OU `
                                           -Container:$Container -Volume:$Volume -Group:$Group -UseGlobalCatalog
        if ($null -eq $aADObjects) {
            return $null
        }
        $hSelectObjectArgs = @{
            "Objects" = $aADObjects 
            "SelectedColumns" = @(@{l="Name"; e={$_.name}}
                                  @{l="Type";e={$_.objectclass}}
                                  @{l="Domain";e={ConvertFrom-DN $_.distinguishedname}}
                                  @{l="Description";e={$_.description}}
                                )
            "Sort" = @{Expression = { $_.name } ; Descending = $false}
            "AutoSelectWhenOneItem" = $true
            "ItemsPerPage" = $ItemsPerPage
            "EmptyArrayMessage" = $NoObjectsMatchingQuery
            "FooterMessage" = ""
            SeparatorColor = $SeparatorColor
            HeaderTextInSeparator = $HeaderTextInSeparator
        }
        if ($OtherMenuItems) { 
            $hSelectObjectArgs.OtherMenuItems = $OtherMenuItems 
        }
        $oSelectedADObject = Select-CLIDialogObjectInArray @hSelectObjectArgs
        switch ($oSelectedADObject.PSTypeNames[0]) {
            "DialogResult.Action.Back" {
                if ($oSelectedADObject.Depth -eq 0) {
                    $oSelectedADObject.Depth += 1
                    return $oSelectedADObject
                }
            }
            "DialogResult.Action.Exit" {
                return $oSelectedADObject
            }
            "DialogResult.Value" {
                if ($ReturnDN.IsPresent) {
                    return $oSelectedADObject.Value.distinguishedname
                } else {
                    $hADUSerQuery = @{
                        Identity = $oSelectedADObject.Value.distinguishedname
                    }
                    if (($null -ne $oCLIUser.Domain) -and ($oCLIUser.Domain -ne "")) {
                        $hADUSerQuery.Server = $oCLIUser.Domain
                    }
                    if ($Properties) {
                        $hADUSerQuery.Properties = $Properties
                    }
                    return Get-ADObject @hADUSerQuery -Computer:$Computer -User:$User -OU:$OU `
                                                      -Container:$Container -Volume:$Volume -Group:$Group
                }
            }
        }
    }
}
