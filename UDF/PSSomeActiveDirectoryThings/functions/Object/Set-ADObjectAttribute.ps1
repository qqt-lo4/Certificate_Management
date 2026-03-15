function Set-ADObjectAttribute {
    <#
    .SYNOPSIS
        Sets one or more attributes on an AD object

    .DESCRIPTION
        Modifies AD object attributes via DirectoryEntry by setting property values
        and committing changes. Supports multiple attributes in a single operation.

    .PARAMETER Object
        The AD object to modify.

    .PARAMETER Attribute
        A hashtable of attribute names and values to set.

    .PARAMETER Credential
        Optional PSCredential for AD authentication.

    .OUTPUTS
        None. The AD object attributes are modified.

    .EXAMPLE
        Set-ADObjectAttribute -Object $user -Attribute @{ description = "New description" }

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [Object]$Object,
        [Parameter(Mandatory, Position = 1)]
        [hashtable]$Attribute,
        [pscredential]$Credential
    )
    $sPath = if ($Object.adspath) {
        $Object.adspath
    } else {
        $Object.Path
    }
    $deObject = if ($Credential) {
        Get-DirectoryEntry -Path $sPath -Credential $Credential
    } else {
        Get-DirectoryEntry -Path $sPath
    }
    foreach ($oAttribute in $Attribute.Keys) {
        $oValue = $Attribute[$oAttribute]
        $deObject.Properties[$oAttribute].Value = $oValue
    }
    $deObject.CommitChanges()
    $deObject.Close()
}
