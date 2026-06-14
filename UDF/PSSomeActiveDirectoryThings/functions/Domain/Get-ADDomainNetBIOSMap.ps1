function Get-ADDomainNetBIOSMap {
    <#
    .SYNOPSIS
        Returns the forest's NetBIOS-name to DNS-name mapping for
        every domain in the current forest.

    .DESCRIPTION
        Reads the crossRef objects in the Configuration partition's
        Partitions container (CN=Partitions,CN=Configuration,
        <forestDN>). Each crossRef carries both nETBIOSName (e.g.
        "FABRIKAM") and nCName (the domain DN, e.g.
        "DC=fabrikam,DC=com"). The function turns the DN into the
        standard dot-form DNS name and builds a hashtable keyed by
        the NetBIOS name.

        Use when callers receive identities tagged with the
        Windows-legacy NetBIOS short name (typical of SCCM
        SMS_R_System.ResourceDomainOrWorkgroup,
        SMS_R_User.WindowsNTDomain, the "domain" prefix of
        DOMAIN\sAMAccountName tokens, ...) and need to feed
        Get-ADObject's -Server which expects a DNS name.

    .PARAMETER Credential
        Optional credentials for the LDAP connection.

    .PARAMETER Server
        Optional explicit AD server / domain DNS name. Defaults to
        a serverless bind that resolves the current domain.

    .OUTPUTS
        [hashtable] - keys = NetBIOS names (case-insensitive,
        compared with -eq), values = DNS form.

    .EXAMPLE
        $hMap = Get-ADDomainNetBIOSMap
        $hMap['FABRIKAM']   # => 'fabrikam.com'
        $hMap['EU']         # => 'eu.fabrikam.com'

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-06-03, Loic Ade) - Initial version.
    #>
    [CmdletBinding()]
    Param(
        [PSCredential]$Credential,
        [string]$Server
    )

    Process {
        $sRootDSEPath = if ($Server) { "LDAP://$Server/RootDSE" } else { 'LDAP://RootDSE' }
        $oRoot = if ($Credential) {
            $sPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password))
            New-Object System.DirectoryServices.DirectoryEntry($sRootDSEPath, $Credential.UserName, $sPwd)
        } else {
            New-Object System.DirectoryServices.DirectoryEntry($sRootDSEPath)
        }
        $sConfigNC = [string]$oRoot.Properties['configurationNamingContext'][0]
        if (-not $sConfigNC) {
            throw "Get-ADDomainNetBIOSMap : unable to read configurationNamingContext from RootDSE."
        }

        $sPartitionsPath = if ($Server) {
            "LDAP://$Server/CN=Partitions,$sConfigNC"
        } else {
            "LDAP://CN=Partitions,$sConfigNC"
        }
        $oPart = if ($Credential) {
            $sPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password))
            New-Object System.DirectoryServices.DirectoryEntry($sPartitionsPath, $Credential.UserName, $sPwd)
        } else {
            New-Object System.DirectoryServices.DirectoryEntry($sPartitionsPath)
        }
        $oSearcher = New-Object System.DirectoryServices.DirectorySearcher($oPart)
        $oSearcher.Filter = '(&(objectClass=crossRef)(nETBIOSName=*))'
        $null = $oSearcher.PropertiesToLoad.Add('nETBIOSName')
        $null = $oSearcher.PropertiesToLoad.Add('nCName')

        $hMap = @{}
        foreach ($oR in $oSearcher.FindAll()) {
            $sNetBIOS = [string]$oR.Properties['netbiosname'][0]
            $sDN      = [string]$oR.Properties['ncname'][0]
            if ($sNetBIOS -and $sDN) {
                # Convert the DN form "DC=foo,DC=bar" to the DNS
                # form "foo.bar". Ignore non-DC RDNs (the partition
                # name is always pure DC=).
                $sDns = (($sDN -split ',') | ForEach-Object {
                    if ($_ -match '^DC=(.+)$') { $Matches[1] }
                }) -join '.'
                if ($sDns) { $hMap[$sNetBIOS] = $sDns }
            }
        }
        return $hMap
    }
}
