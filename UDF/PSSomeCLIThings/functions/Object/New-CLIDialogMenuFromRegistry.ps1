function New-CLIDialogMenuFromRegistry {
    <#
    .SYNOPSIS
        Builds object dialog menu rows from the menu registry for a given object.

    .DESCRIPTION
        Collects the buttons registered (via Register-CLIMenuButton) for the object's
        resolved type tokens (see Resolve-CLIMenuType), filters them by requested view
        and per-button Filter, groups them by MenuRow, orders everything, and returns
        ready-to-use CLIDialogObjectsRow objects.

        Ordering:
            - Rows are ordered first by the specificity of the most-specific type token
              that contributes to them (type-specific rows before generic ones, e.g.
              "Find Endpoint in" registered on "Computer" lands last), then by
              declaration order (registration order of their first button).
            - Buttons within a row are ordered by Order, then declaration order.

        Returns an empty array when no button matches, so the caller can safely
        concatenate it with a legacy menu.

    .PARAMETER Object
        The object the menu is built for. Its type tokens and the per-button Filter
        are evaluated against it.

    .PARAMETER Function
        The requested view (compact form). Empty/omitted means the base view. A button
        is kept when its Function list contains "*" or this value.

    .OUTPUTS
        Array of CLIDialogObjectsRow objects (possibly empty).

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-06-14 - Loïc Ade
            - Initial release. Registry-driven menu builder for the object dialog
              engine (type-hierarchy ordering, view + Filter selection).
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$Object,
        [Parameter(Position = 1)]
        [string]$Function
    )

    if ($Global:CLIMenuRegistry -isnot [hashtable]) {
        return @()
    }

    $aTokens = Resolve-CLIMenuType -Object $Object
    $sFunc = if ($Function) { $Function.Replace(' ', '') } else { '' }

    # Collect matching buttons, tagging each with the rank of its type token and a
    # global sequence number (declaration order across tokens / ordered registry).
    $aCandidates = New-Object System.Collections.Generic.List[object]
    $iRank = 0
    $iSeq  = 0
    foreach ($sToken in $aTokens) {
        if ($Global:CLIMenuRegistry.ContainsKey($sToken)) {
            foreach ($oButton in $Global:CLIMenuRegistry[$sToken].Values) {
                $aButtonFunc = if ($null -eq $oButton.Function) { @('') } else { @($oButton.Function) }
                if (-not (('*' -in $aButtonFunc) -or ($sFunc -in $aButtonFunc))) {
                    continue
                }
                if ($oButton.Filter) {
                    $bShow = $true
                    try {
                        $bShow = [bool](& $oButton.Filter $Object)
                    } catch {
                        Write-Debug "Register-CLIMenuButton filter for '$($oButton.Name)' threw: $_"
                        $bShow = $false
                    }
                    if (-not $bShow) { continue }
                }
                $aCandidates.Add([pscustomobject]@{
                    Button    = $oButton
                    TokenRank = $iRank
                    Seq       = $iSeq
                })
                $iSeq++
            }
        }
        $iRank++
    }

    if ($aCandidates.Count -eq 0) {
        return @()
    }

    # Group by MenuRow; a row inherits the most specific token rank and the earliest
    # declaration sequence among its buttons.
    $aRows = New-Object System.Collections.Generic.List[object]
    foreach ($oGroup in ($aCandidates | Group-Object { $_.Button.MenuRow })) {
        $iRowTokenRank = ($oGroup.Group | Measure-Object -Property TokenRank -Minimum).Minimum
        $iRowSeq       = ($oGroup.Group | Measure-Object -Property Seq -Minimum).Minimum
        $aRows.Add([pscustomobject]@{
            MenuRow   = $oGroup.Name
            Items     = $oGroup.Group
            TokenRank = $iRowTokenRank
            Seq       = $iRowSeq
        })
    }

    $aSortedRows = $aRows | Sort-Object -Property TokenRank, Seq

    $aResult = New-Object System.Collections.Generic.List[object]
    foreach ($oRow in $aSortedRows) {
        $aSortedItems = $oRow.Items | Sort-Object -Property @{ Expression = { $_.Button.Order } }, @{ Expression = { $_.Seq } }
        $aButtons = @(
            foreach ($oItem in $aSortedItems) {
                $oBtn = $oItem.Button
                $hArgs = @{ Text = $oBtn.Text; Object = $oBtn.Object }
                if ($oBtn.ButtonArgs) { $hArgs += $oBtn.ButtonArgs }
                New-CLIDialogButton @hArgs
            }
        )
        $aResult.Add((New-CLIDialogObjectsRow -Header $oRow.MenuRow -Row $aButtons))
    }

    return , $aResult.ToArray()
}
