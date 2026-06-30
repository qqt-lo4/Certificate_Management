function Get-CLIObjectPropertyList {
    <#
    .SYNOPSIS
        Builds the ordered property descriptor list of an object dialog view.

    .DESCRIPTION
        Property counterpart of New-CLIDialogMenuFromRegistry. Produces the list of
        property descriptors (@{N=<label>; E=<scriptblock>; ...}) shown at the top of an
        object dialog view, merging the declarative property registry (see
        Register-CLIObjectProperty) with the legacy convention functions.

        Resolution order for a requested view F on an object of type T (faithful to the
        legacy Get-<Type>[-<Func>]_ObjectProperties chain, so views without their own
        property list inherit the type's base properties, and a legacy function that
        returns nothing keeps suppressing that inheritance):

            1. Registry entries whose Function matches F (or "*") for T's resolved type
               tokens. If any entry addresses F (visible or a -Hide), the result is
               registry-driven (after hide/override/order/anchor/Filter resolution).
            2. Legacy Get-<T>-<F>_ObjectProperties, then Get-<F>_ObjectProperties.
            3. Base inheritance (only when F is non-empty): registry entries for the BASE
               view (Function "") of T's tokens - the type's default property block.
            4. Legacy Get-<T>_ObjectProperties.
            5. Empty.

        Registry collection details: type tokens come from Resolve-CLIMenuType
        (specific -> generic); within that, entries keep registration order; -Hide
        removes a Name; a repeated Name keeps the first (most specific) occurrence;
        ordering is type tier, then Order, then declaration, then the -After/-Before
        anchors; a per-entry -Filter that returns false (or throws) drops the property.

    .PARAMETER Object
        The object whose property list is built.

    .PARAMETER Function
        The requested view (compact form, spaces removed). Empty/omitted = base view.

    .OUTPUTS
        Array of property descriptors (@{N; E; ...}), possibly empty.

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        Dependencies:
            Resolve-CLIMenuType (PSSomeCLIThings)
            Get-Function        (PSSomeCoreThings)

        CHANGELOG:

        Version 1.0.0 - 2026-06-17 - Loïc Ade
            - Initial release. Registry-driven property list builder with per-view
              Function selection, per-object Filter, hide, and anchor (-After/-Before)
              / numeric (-Order) ordering.
            - Faithful to the legacy Get-<Type>[-<Func>]_ObjectProperties chain: the
              registry-specific view wins; otherwise the legacy Get-<T>-<F> / Get-<F>
              functions are consulted (so a $null-returning content-view function still
              suppresses the base block); otherwise a non-base view inherits the type's
              base (Function "") registry properties; otherwise the legacy base function.
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$Object,
        [Parameter(Position = 1)]
        [string]$Function
    )

    $sFunc = if ($Function) { $Function.Replace(' ', '') } else { '' }
    $sType = $Object.PSTypeNames[0].Replace(' ', '')
    $aTokens = if ($Global:CLIPropertyRegistry -is [hashtable]) { Resolve-CLIMenuType -Object $Object } else { @() }

    # Collect the registry property descriptors addressing a given view token.
    # Returns @{ Any = <any registry entry matched this view, visible or hidden>;
    #            Descriptors = <ordered render descriptors @{N;E;...}> }.
    function Get-RegistrySet {
        Param([string]$TargetFunc)

        $aCandidates = New-Object System.Collections.ArrayList
        $hHidden     = @{}
        $hSeenName   = @{}
        $bAny        = $false
        $iRank = 0
        $iSeq  = 0
        foreach ($sToken in $aTokens) {
            if ($Global:CLIPropertyRegistry.ContainsKey($sToken)) {
                foreach ($oDesc in $Global:CLIPropertyRegistry[$sToken].Values) {
                    $aF = if ($null -eq $oDesc.Function) { @('') } else { @($oDesc.Function) }
                    if (-not (('*' -in $aF) -or ($TargetFunc -in $aF))) { continue }
                    $bAny = $true
                    if ($oDesc.Hidden) { $hHidden[$oDesc.Name] = $true; continue }
                    if ($oDesc.Empty)  { continue }   # marker only: drives the view, adds nothing
                    if ($hSeenName.ContainsKey($oDesc.Name)) { continue }
                    if ($oDesc.Filter) {
                        $bShow = $true
                        try { $bShow = [bool](& $oDesc.Filter $Object) }
                        catch { Write-Debug "Register-CLIObjectProperty filter for '$($oDesc.Name)' threw: $_"; $bShow = $false }
                        if (-not $bShow) { continue }
                    }
                    $hSeenName[$oDesc.Name] = $true
                    [void]$aCandidates.Add([pscustomobject]@{ Descriptor = $oDesc; Rank = $iRank; Seq = $iSeq })
                    $iSeq++
                }
            }
            $iRank++
        }

        $aVisible = @($aCandidates | Where-Object { -not $hHidden.ContainsKey($_.Descriptor.Name) })
        if ($aVisible.Count -eq 0) { return @{ Any = $bAny; Descriptors = @() } }

        $aOrdered = $aVisible | Sort-Object -Property `
            @{ Expression = { $_.Rank } }, `
            @{ Expression = { $_.Descriptor.Order } }, `
            @{ Expression = { $_.Seq } }

        $aRes  = New-Object System.Collections.ArrayList
        $aPend = New-Object System.Collections.ArrayList
        foreach ($o in $aOrdered) {
            if ($o.Descriptor.After -or $o.Descriptor.Before) { [void]$aPend.Add($o) } else { [void]$aRes.Add($o) }
        }
        $bProgress = $true
        while (($aPend.Count -gt 0) -and $bProgress) {
            $bProgress = $false
            foreach ($o in @($aPend)) {
                $sAnchor = if ($o.Descriptor.After) { $o.Descriptor.After } else { $o.Descriptor.Before }
                $iIdx = -1
                for ($i = 0; $i -lt $aRes.Count; $i++) { if ($aRes[$i].Descriptor.Name -eq $sAnchor) { $iIdx = $i; break } }
                if ($iIdx -ge 0) {
                    $iInsert = if ($o.Descriptor.After) { $iIdx + 1 } else { $iIdx }
                    [void]$aRes.Insert($iInsert, $o)
                    $aPend.Remove($o)
                    $bProgress = $true
                }
            }
        }
        foreach ($o in $aPend) { [void]$aRes.Add($o) }

        $aDesc = @(
            foreach ($o in $aRes) {
                $d = $o.Descriptor
                $h = @{ N = $d.Header; E = $d.Expression }
                if ($d.Options) { foreach ($k in $d.Options.Keys) { $h[$k] = $d.Options[$k] } }
                $h
            }
        )
        return @{ Any = $bAny; Descriptors = $aDesc }
    }

    # 1. Registry entries specific to the requested view.
    $oSpecific = Get-RegistrySet -TargetFunc $sFunc
    if ($oSpecific.Any) { return , $oSpecific.Descriptors }

    # 2. Legacy dedicated function for this view (e.g. dynamic All-Info views, or a
    #    $null-returning content-view function that suppresses the base block).
    if ($sFunc) {
        $f = Get-Function "Get-$sType-$sFunc`_ObjectProperties"
        if ($f) { return (. $f $Object) }
        $f = Get-Function "Get-$sFunc`_ObjectProperties"
        if ($f) { return (. $f $Object) }
    }

    # 3. Base inheritance: a non-base view with no list of its own shows the type's
    #    base (Function "") registry properties.
    if ($sFunc) {
        $oBase = Get-RegistrySet -TargetFunc ''
        if ($oBase.Any) { return , $oBase.Descriptors }
    }

    # 4. Legacy base property function (un-migrated types).
    $f = Get-Function "Get-$sType`_ObjectProperties"
    if ($f) { return (. $f $Object) }

    return @()
}
