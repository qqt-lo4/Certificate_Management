function ConvertTo-ADObject {
    <#
    .SYNOPSIS
        Converts a DirectoryEntry to a custom AD object

    .DESCRIPTION
        Transforms a System.DirectoryServices.DirectoryEntry into an ordered hashtable
        with typed PSTypeNames and converted property values.

    .PARAMETER InputObject
        The DirectoryEntry object to convert. Accepts pipeline input.

    .OUTPUTS
        OrderedDictionary. A custom AD object with AdditionalProperties and typed names.

    .EXAMPLE
        $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://DC=contoso,DC=com")
        $de | ConvertTo-ADObject

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [object]$InputObject
    )
    $hADObject = [ordered]@{
        AdditionalProperties = @{
            Path = $oResult.Path
            SearchResult = $oResult
            Properties = @()
        }
    }
    $aKeys = $InputObject.Properties.Keys | Sort-Object
    foreach ($p in $aKeys) {
        $hADObject[$p] = Convert-ADObjectValue -Property $p -Value ($InputObject.Properties[$p])
        $hADObject.AdditionalProperties.Properties += $p
    }
    $hADObject.psobject.TypeNames.Insert(0, "ADObject")
    $hADObject.psobject.TypeNames.Insert(0, "AD" + $hADObject.Properties.objectclass)
    return $hADObject
}