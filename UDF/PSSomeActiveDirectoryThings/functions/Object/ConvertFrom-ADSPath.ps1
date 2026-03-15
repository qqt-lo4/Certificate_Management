function ConvertFrom-ADSPath {
    <#
    .SYNOPSIS
        Parses an ADS path into its components (protocol, server, DN)

    .DESCRIPTION
        Extracts the protocol (LDAP/GC), optional server, and distinguished name
        from an ADS path string or AD object's adspath property.

    .PARAMETER ADObject
        An AD object with an adspath property, or an ADS path string.

    .OUTPUTS
        System.Collections.Hashtable. Contains protocol, server, and dn keys.

    .EXAMPLE
        ConvertFrom-ADSPath -ADObject "LDAP://dc01/CN=User,DC=contoso,DC=com"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADObject
    )
    $sRegEx = "(?<protocol>(LDAP|GC)://)((?<server>.*)/)?(?<dn>.+)"
    $sADSPath = if ($ADObject.adspath) {
        $ADObject.adspath
    } elseif (($ADObject -is [string]) -and ($ADObject -match $sRegEx)) {
        $ADObject
    } else {
        ""
    }
    if ($sADSPath -eq "") {
        throw "`$ADObject does not have adspath property"
    } else {
        $ss = Select-String -InputObject $sADSPath -Pattern $sRegex -AllMatches
        return $ss | Convert-MatchInfoToHashtable -ExcludeNumbers -ExcludeNull
    }
}