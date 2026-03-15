function Get-ADComputerDomain {
    <#
    .SYNOPSIS
        Retrieves the domain distinguished name for a computer account

    .DESCRIPTION
        Searches the Global Catalog for a computer by sAMAccountName and returns
        the domain portion (DC=...) of its distinguished name.

    .PARAMETER Name
        The computer name (sAMAccountName without the trailing $).

    .OUTPUTS
        System.String. The domain DN (e.g., "DC=contoso,DC=com"), or empty string if not found.

    .EXAMPLE
        Get-ADComputerDomain -Name "WORKSTATION01"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory)]
        [string]$Name
    )
    Begin {
        function Split-DN {
            Param(
                [string]$DN
            )
            $iDC = $DN.IndexOf("DC=")
            if ($iDC -eq -1) {
                $iDC = $DN.IndexOf("dc=")
            }
            return [pscustomobject]@{
                Path = $DN.Substring(0, $iDC - 1)
                Domain = $DN.Substring($iDC)
            }
        }

        [System.DirectoryServices.DirectoryEntry] $de = New-Object System.DirectoryServices.DirectoryEntry("GC://RootDSE")
        $sServer = "GC://" + $de.Properties["rootDomainNamingContext"][0].ToString();
        $de = New-Object System.DirectoryServices.DirectoryEntry($sServer)
        $ds = New-Object System.DirectoryServices.DirectorySearcher($de);
        $ds.Filter = "(&(objectCategory=Computer)(objectClass=computer)(sAMAccountName=$Name`$))"
    }
    Process {
        $oResult = $ds.FindAll()
        if ($Filter -and ($Filter -ne "*")) {
            $oResult = $oResult | Where-Object $Filter
        }
        if ($oResult.Count -ge 1) {
            return (Split-DN $oResult[0].Properties.distinguishedname[0]).Domain
        } else {
            ""
        }
    }
}