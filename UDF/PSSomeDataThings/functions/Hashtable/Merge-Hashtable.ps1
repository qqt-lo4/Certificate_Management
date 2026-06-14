function Merge-Hashtable {
    <#
    .SYNOPSIS
        Recursively merges two hashtables into a new one

    .DESCRIPTION
        Deep-merges HashtableA and HashtableB into a brand-new hashtable, leaving both
        inputs untouched. Nested dictionaries are merged recursively; for any leaf key
        present in both, the value from HashtableB wins. Either input may be $null.

        Accepts any IDictionary (e.g. the OrderedDictionary produced by
        ConvertTo-Hashtable), not only [hashtable].

    .PARAMETER HashtableA
        The base dictionary. May be $null.

    .PARAMETER HashtableB
        The overriding dictionary; its values win on leaf conflicts. May be $null.

    .OUTPUTS
        [hashtable] (a new hashtable), or $null when both inputs are $null.

    .EXAMPLE
        Merge-Hashtable @{ a = @{ x = 1 } } @{ a = @{ y = 2 } }
        # -> @{ a = @{ x = 1; y = 2 } }

    .EXAMPLE
        Merge-Hashtable @{ a = 1; b = 2 } @{ b = 3; c = 4 }
        # -> @{ a = 1; b = 3; c = 4 }   (b from the second hashtable wins)

    .NOTES
        Author  : Loïc Ade
        Version : 2.0.0

        CHANGELOG:

        Version 2.0.0 - 2026-06-14 - Loïc Ade
            - Rewritten as a recursive deep merge returning a new hashtable
              (the previous version did a shallow, in-place merge).
            - Nested dictionaries are merged recursively; values from HashtableB
              win on leaf conflicts.
            - Accepts any IDictionary (including the OrderedDictionary returned by
              ConvertTo-Hashtable), not only [hashtable]. Either input may be $null.
            - Parameters renamed from InputObject/MergeWith to HashtableA/HashtableB.
              Consolidated from the copy formerly embedded in Get-UserAndAppScriptConfig
              (PSSomeCoreThings).

        Version 1.0.0 - Loïc Ade
            - Initial release. Shallow, in-place merge of two hashtables.
    #>
    Param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [System.Collections.IDictionary]$HashtableA,
        [Parameter(Position = 1)]
        [AllowNull()]
        [System.Collections.IDictionary]$HashtableB
    )
    if (($null -eq $HashtableA) -and ($null -eq $HashtableB)) {
        return $null
    } elseif (($null -eq $HashtableA) -and ($null -ne $HashtableB)) {
        return Copy-Hashtable $HashtableB
    } elseif (($null -ne $HashtableA) -and ($null -eq $HashtableB)) {
        return Copy-Hashtable $HashtableA
    } else {
        $hResult = @{}
        foreach ($p in $HashtableA.Keys) {
            # key present in both: deep-merge nested dictionaries, otherwise B wins
            if ($p -in $HashtableB.Keys) {
                if (($HashtableA[$p] -is [System.Collections.IDictionary]) -and ($HashtableB[$p] -is [System.Collections.IDictionary])) {
                    $hResult[$p] = Merge-Hashtable $HashtableA[$p] $HashtableB[$p]
                } else {
                    $hResult[$p] = $HashtableB[$p]
                }
            } else {
                $hResult[$p] = $HashtableA[$p]
            }
        }
        foreach ($p in $HashtableB.Keys) {
            if ($p -notin $HashtableA.Keys) {
                $hResult[$p] = $HashtableB[$p]
            }
        }
        return $hResult
    }
}
