function Get-ADWMIFilter {
    <#
    .SYNOPSIS
        Retrieves a Group Policy WMI filter (msWMI-Som object) from AD.

    .DESCRIPTION
        Reads the msWMI-Som object stored under
        CN=SOM,CN=WMIPolicy,CN=System,<domainDN> and returns its main
        properties: display name, description, author, creation/change
        timestamps, and the WQL queries it contains.

        The function accepts either a WMI filter GUID (from a GPO's
        gPCWQLFilter attribute — the "{GUID}" part of the
        "[domain;{GUID};0]" format) or the raw gPCWQLFilter value.

    .PARAMETER Id
        WMI filter GUID, enclosed in braces ({GUID}) or not. Also
        accepts the full gPCWQLFilter value "[domain;{GUID};0]" for
        convenience.

    .PARAMETER Server
        Domain FQDN or domain controller to query. Defaults to
        $env:USERDNSDOMAIN.

    .PARAMETER Credential
        Optional PSCredential for authentication.

    .OUTPUTS
        PSCustomObject with properties:
            Id, Name, Description, Author, CreationDate, ChangeDate,
            Queries (array of WQL strings).
        Returns $null if the filter cannot be read.

    .EXAMPLE
        Get-ADWMIFilter -Id '{12345678-abcd-...}'

    .EXAMPLE
        # Resolve the WMI filter referenced by a GPO
        $oGPO = Get-ADGroupPolicy -Identity 'Default Domain Policy' -Properties gPCWQLFilter
        Get-ADWMIFilter -Id $oGPO.gpcwqlfilter

    .NOTES
        Author  : Loic Ade
        Version : 1.0.0

        1.0.0 (2026-04-13) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [string]$Id,

        [string]$Server = $env:USERDNSDOMAIN,

        [AllowNull()]
        [PSCredential]$Credential
    )

    Process {
        # Extract the GUID from either a raw "{GUID}" or a full
        # gPCWQLFilter value "[domain.fqdn;{GUID};0]".
        if ($Id -notmatch '\{[0-9a-fA-F\-]+\}') {
            Write-Warning "Get-ADWMIFilter : cannot extract a GUID from '$Id'"
            return $null
        }
        $sGuid = $Matches[0]

        # Resolve the domain DN to build the filter object path
        $sRootDSEPath = if ($Server) { "LDAP://$Server/RootDSE" } else { "LDAP://RootDSE" }
        $oRootDSE = Get-DirectoryEntry -Path $sRootDSEPath -Credential $Credential
        $sDomainDN = $oRootDSE.Properties["defaultNamingContext"][0].ToString()

        $sFilterDN = "CN=$sGuid,CN=SOM,CN=WMIPolicy,CN=System,$sDomainDN"
        $sFilterPath = if ($Server) { "LDAP://$Server/$sFilterDN" } else { "LDAP://$sFilterDN" }

        # Helper: safe string read from a multi-valued property collection.
        # Returns $null when the property is missing, empty, or its first
        # element is itself null (which can happen on cross-domain binds).
        function Get-DEStringProperty {
            Param($DirectoryEntry, [string]$Name)
            try {
                $oCol = $DirectoryEntry.Properties[$Name]
                if (-not $oCol -or $oCol.Count -eq 0) { return $null }
                $oVal = $oCol[0]
                if ($null -eq $oVal) { return $null }
                return $oVal.ToString()
            } catch {
                return $null
            }
        }

        $oDE = $null
        $sName = $null
        try {
            $oDE = Get-DirectoryEntry -Path $sFilterPath -Credential $Credential
            $sName = Get-DEStringProperty $oDE 'msWMI-Name'
            if (-not $sName) { return $null }
        } catch {
            Write-Warning "Get-ADWMIFilter : cannot read $sFilterDN - $_"
            return $null
        }

        # msWMI-Parm2 encodes the WQL queries as:
        #   "<count>;3;<nsLen>;<namespace>;<qLen>;<query>;..."
        # (one triplet per query). Parse it into an array of raw WQL strings.
        $aQueries = @()
        $sParm2 = Get-DEStringProperty $oDE 'msWMI-Parm2'
        if ($sParm2) {
            try {
                $aTokens = $sParm2.Split(';')
                $iPos = 0
                $iCount = [int]$aTokens[$iPos]; $iPos++
                for ($i = 0; $i -lt $iCount; $i++) {
                    # Skip the constant "3" marker
                    $iPos++
                    # Namespace length + value
                    $iNsLen = [int]$aTokens[$iPos]; $iPos++
                    $iPos++  # namespace string (length already known)
                    # Query length + value
                    $iPos++  # query length
                    $aQueries += $aTokens[$iPos]; $iPos++
                }
            } catch {
                Write-Verbose "Get-ADWMIFilter : failed to parse msWMI-Parm2 for $sGuid - $_"
            }
        }

        [PSCustomObject][ordered]@{
            Id           = $sGuid
            Name         = $sName
            Description  = Get-DEStringProperty $oDE 'msWMI-Parm1'
            Author       = Get-DEStringProperty $oDE 'msWMI-Author'
            CreationDate = Get-DEStringProperty $oDE 'msWMI-CreationDate'
            ChangeDate   = Get-DEStringProperty $oDE 'msWMI-ChangeDate'
            Queries      = $aQueries
        }
    }
}
