function Resolve-CLIMenuType {
    <#
    .SYNOPSIS
        Resolves the ordered list of menu type tokens applicable to an object.

    .DESCRIPTION
        Produces the ordered token list used by New-CLIDialogMenuFromRegistry to
        collect and order an object's menu buttons, from most specific to most
        generic:

            1. The object's PSTypeNames (spaces removed), in order. No filtering is
               done: noise tokens (e.g. System.Object) simply match no registered
               buttons and are harmless.
            2. The transitive IS-A correspondences (see Register-CLIMenuTypeAlias),
               appended after the native tokens, de-duplicated.
            3. "*" (universal token) last.

        Duplicates are removed case-insensitively while preserving first-seen order.

    .PARAMETER Object
        The object whose applicable menu type tokens are resolved.

    .OUTPUTS
        [string[]] ordered from most specific to most generic.

    .EXAMPLE
        Resolve-CLIMenuType -Object $adComputer
        # e.g. ADComputer, ADObject, Computer, <.NET types>, *

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-06-14 - Loïc Ade
            - Initial release. Native PSTypeNames + transitive type aliases + "*".
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$Object
    )

    $aResult = New-Object System.Collections.Generic.List[string]
    $hSeen   = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

    # 1. Native type tokens, in order, spaces removed (no filtering).
    foreach ($sTypeName in $Object.PSTypeNames) {
        $sToken = $sTypeName.Replace(' ', '')
        if ($sToken -and $hSeen.Add($sToken)) {
            $aResult.Add($sToken)
        }
    }

    # 2. Transitive IS-A correspondences, appended after the natives. The loop walks
    #    newly appended tokens too, so chains (A -> B -> C) are resolved; $hSeen
    #    prevents cycles and duplicates.
    if ($Global:CLIMenuTypeAliases -is [hashtable]) {
        $i = 0
        while ($i -lt $aResult.Count) {
            $sCurrent = $aResult[$i]
            if ($Global:CLIMenuTypeAliases.ContainsKey($sCurrent)) {
                foreach ($sAlias in $Global:CLIMenuTypeAliases[$sCurrent]) {
                    if ($sAlias -and $hSeen.Add($sAlias)) {
                        $aResult.Add($sAlias)
                    }
                }
            }
            $i++
        }
    }

    # 3. Universal token last.
    if ($hSeen.Add('*')) {
        $aResult.Add('*')
    }

    return , $aResult.ToArray()
}
