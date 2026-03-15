function Get-ADDNObject {
    <#
    .SYNOPSIS
        Retrieves AD objects from a list of distinguished names

    .DESCRIPTION
        Queries Active Directory to resolve a list of distinguished names into
        full AD objects. Automatically groups DNs by domain for efficient querying
        across multi-domain forests. Supports Global Catalog and additional properties.

    .PARAMETER Credential
        PSCredential for AD authentication.

    .PARAMETER Properties
        Properties to load from AD.

    .PARAMETER AdditionalProperties
        Extra properties loaded in a separate query and merged into results.

    .PARAMETER Server
        The AD server to connect to. Cannot be used when DNs span multiple domains.

    .PARAMETER DN
        The distinguished name(s) to resolve.

    .PARAMETER UseGlobalCatalog
        If specified, uses the Global Catalog (GC://). Aliases: GC, GlobalCatalog.

    .OUTPUTS
        Custom AD object(s) resolved from the DN list.

    .EXAMPLE
        $g = Get-ADObject -Identity "CN=Test,OU=Groups,DC=lan,DC=example,DC=com"
        Get-ADDNObject -DN $g.member

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
        Version 1.0: First version
    #>
    
    Param(
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]$Credential,

        [ValidateNotNullOrEmpty()]
        [Alias("Property")]
        [string[]]$Properties,

        [ValidateNotNullOrEmpty()]
        [string[]]$AdditionalProperties,

        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [ValidateNotNull()]
        [string[]]$DN,

        [Alias("GC", "GlobalCatalog")]
        [switch]$UseGlobalCatalog
    )
    Begin {
        function New-DNLdapFilter {
            Param(
                [string[]]$DN
            )
            $aResult = @()
            $aResult += "(|"
            foreach ($sDN in $DN) {
                $aResult += "(distinguishedName=$sDN)"
            }
            $aResult += ")"
            return ($aResult -join "")
        }

        $aGroupedDN = Group-DNByDomain -DNList $DN
        if ($Server -and ($aGroupedDN.Count -gt 1)) {
            throw "Can't specify server : there is more than one domain in the DN list"
        }
        $aServerList = if ($Server) { $Server } else { $aGroupedDN.Keys }

        $aResults = @()
        $defaultDisplaySet = 'distinguishedname','givenname','Name','objectclass','objectguid','samaccountname','objectsid','sn','userprincipalname'
        $defaultDisplayPropertySet = New-Object System.Management.Automation.PSPropertySet('DefaultDisplayPropertySet',[string[]]$defaultDisplaySet)
        $PSStandardMembers = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropertySet)

        foreach ($sDomain in $aServerList) {
            $sPath = if ($UseGlobalCatalog) { "GC://$sDomain" } else { "LDAP://$sDomain" }
            $de = Connect-DirectoryEntry -Server $sPath -Credential $Credential
            $ds = New-Object System.DirectoryServices.DirectorySearcher($de);

            foreach ($sProperty in $Properties) {
                $ds.PropertiesToLoad.Add($sProperty) | Out-Null
            }
            $ds.Filter = New-DNLdapFilter -DN $DN

            $aADResults = $ds.FindAll()
            $aGroupedADResults = $aADResults | Group-Object -Property Path -AsHashTable
            if ($AdditionalProperties) {
                $ds.PropertiesToLoad.Clear()
                foreach ($sProperty in $AdditionalProperties) {
                    $ds.PropertiesToLoad.Add($sProperty) | Out-Null
                }
                $aADResultsAdditionalProp = $ds.FindAll()
            } else {
                $aADResultsAdditionalProp = $null
            }
            $aGroupedADAdditionalPropResults = if ($null -eq $aADResultsAdditionalProp) {
                $null
            } else {
                $aADResultsAdditionalProp | Group-Object -Property Path -AsHashTable
            }

            foreach ($sADObjectPath in $aGroupedADResults.Keys) {
                $hADObject = @{
                    AdditionalProperties = @{
                        Path = $sADObjectPath
                        SearchResult = $aGroupedADResults[$sADObjectPath]
                        AdditionalPropSearchResult = if ($AdditionalProperties) { $aGroupedADAdditionalPropResults[$sADObjectPath] } else { $null }
                    }
                }
                foreach ($p in $hADObject.AdditionalProperties.SearchResult.Properties.Keys) {
                    $oValue = $hADObject.AdditionalProperties.SearchResult.Properties[$p]
                    if (($null -ne $oValue) -and ($oValue -ne @())) {
                        $hADObject[$p] = Convert-ADObjectValue -Property $p -Value ($oValue)    
                    } else {
                        $hADObject[$p] = $null
                    }
                }
                if ($AdditionalProperties) {
                    $oAdditionalPropResult = $hADObject.AdditionalProperties.AdditionalPropSearchResult
                    foreach ($p in $oAdditionalPropResult.Properties.Keys) {
                        $hADObject[$p] = Convert-ADObjectValue -Property $p -Value ($oAdditionalPropResult.Properties[$p])
                    }   
                }
                $oNewResult = New-Object -TypeName psobject -Property $hADObject
                $oNewResult | Add-Member MemberSet PSStandardMembers $PSStandardMembers
                $oNewResult.psobject.TypeNames.Insert(0, "AD" + $oNewResult.objectclass)
                $aResults += $oNewResult 
            }
        }
    }
    Process {

    }
    End {
        return $aResults
    }
}
