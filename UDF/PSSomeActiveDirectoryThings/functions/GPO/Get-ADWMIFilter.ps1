function Get-ADWMIFilter {
    <#
    .SYNOPSIS
        Retrieves Group Policy WMI filter(s) (msWMI-Som object) from AD.

    .DESCRIPTION
        Reads msWMI-Som objects stored under
        CN=SOM,CN=WMIPolicy,CN=System,<domainDN> and returns their main
        properties: display name, description, author, creation/change
        timestamps, and the WQL queries they contain.

        Supports two modes:
        - With -Id : returns the single filter matching that GUID (or
          the GUID embedded in a gPCWQLFilter "[domain;{GUID};0]" value).
        - Without -Id : enumerates every msWMI-Som object in the target
          domain (via Get-ADObject -WMIFilter) and emits one object per
          filter.

    .PARAMETER Id
        WMI filter GUID, enclosed in braces ({GUID}) or not. Also
        accepts the full gPCWQLFilter value "[domain;{GUID};0]" for
        convenience. When omitted, every filter of the target domain
        is returned.

    .PARAMETER Server
        Domain FQDN or domain controller to query. Defaults to
        $env:USERDNSDOMAIN.

    .PARAMETER Credential
        Optional PSCredential for authentication.

    .OUTPUTS
        PSCustomObject with properties:
            Id, Name, Description, Author, CreationDate, ChangeDate,
            Queries (array of WQL strings, kept for backward-compat),
            QueryDetails (array of PSCustomObject with Language, Namespace
            and Query for each query in the filter).
        CreationDate / ChangeDate are returned as [DateTime] when AD stores
        a parseable Generalized Time value (the on-wire format is
        YYYYMMDDHHmmss.ffffff±mmm); the raw string is returned as a
        fallback when parsing fails so unexpected values stay visible.
        Returns $null if the filter cannot be read.

    .EXAMPLE
        Get-ADWMIFilter -Id '{12345678-abcd-...}'

    .EXAMPLE
        # Resolve the WMI filter referenced by a GPO
        $oGPO = Get-ADGroupPolicy -Identity 'Default Domain Policy' -Properties gPCWQLFilter
        Get-ADWMIFilter -Id $oGPO.gpcwqlfilter

    .EXAMPLE
        # List every WMI filter of the current domain
        Get-ADWMIFilter | Format-Table Name, Description

    .EXAMPLE
        # Enumerate every filter of a specific domain (forest scenarios)
        Get-ADWMIFilter -Server child.contoso.com -Credential $cred

    .NOTES
        Author  : Loic Ade
        Version : 1.1.0

        1.1.0 (2026-04-29) - Add enumeration mode (no -Id) listing every
                             msWMI-Som object of the target domain via
                             Get-ADObject -WMIFilter.
        1.0.0 (2026-04-13) - Initial version
    #>
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline)]
        [string]$Id,

        [string]$Server = $env:USERDNSDOMAIN,

        [AllowNull()]
        [PSCredential]$Credential
    )

    Process {
        # When invoked without -Id, enumerate every msWMI-Som object of
        # the target domain via Get-ADObject -WMIFilter and recurse for
        # each GUID — the per-filter parsing below stays untouched.
        if (-not $Id) {
            $hSomParams = @{
                WMIFilter   = $true
                Properties  = @('name')
                SearchScope = [System.DirectoryServices.SearchScope]::Subtree
                Server      = $Server
            }
            if ($Credential) { $hSomParams['Credential'] = $Credential }

            $aSoms = @()
            try {
                $aSoms = @(Get-ADObject @hSomParams)
            } catch {
                Write-Warning "Get-ADWMIFilter : enumeration failed on '$Server' - $_"
                return
            }

            foreach ($oSom in $aSoms) {
                if (-not $oSom.name) { continue }
                Get-ADWMIFilter -Id $oSom.name -Server $Server -Credential $Credential
            }
            return
        }

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

        # msWMI-Parm2 encodes the WQL queries as a single ';'-separated string.
        # After Split(';') the tokens lay out as:
        #
        #   [0]    = <count>
        #   [1..6] = <marker>;<nsLen>;<qLen>;<language>;<namespace>;<query>   (block 1)
        #   [7..12] = idem (block 2)
        #   ...
        #
        # Six tokens per block, query value last → block n (1-based) puts the
        # query at index n*6. Layout reverse-engineered from real msWMI-Parm2
        # dumps: the MS-published variant ("<count>;3;<nsLen>;<namespace>;
        # <qLen>;<query>") was missing the <language> slot and made earlier
        # versions of this parser return the namespace as the query.
        #
        # Limitation: a literal ';' inside a WQL string would over-split the
        # block and return a partial query. <qLen> would let us reconstruct
        # the original substring by character count if that ever mattered;
        # production WMI filters don't embed ';' inside literals so a naive
        # index walk is enough.
        # Within each 6-token block the query is the LAST token (offset +5),
        # the namespace the one before it (+4), and the language the one
        # before that (+3). $iBase points at the first token of block n.
        $aQueryDetails = @()
        $sParm2 = Get-DEStringProperty $oDE 'msWMI-Parm2'
        if ($sParm2) {
            try {
                $aTokens = $sParm2.Split(';')
                $iCount = [int]$aTokens[0]
                $iBlockSize = 6
                $aQueryDetails = @(
                    for ($i = 1; $i -le $iCount; $i++) {
                        $iBase = $i * $iBlockSize
                        [PSCustomObject][ordered]@{
                            Language  = $aTokens[$iBase - 2]
                            Namespace = $aTokens[$iBase - 1]
                            Query     = $aTokens[$iBase]
                        }
                    }
                )
            } catch {
                Write-Verbose "Get-ADWMIFilter : failed to parse msWMI-Parm2 for $sGuid - $_"
            }
        }

        # msWMI-CreationDate / msWMI-ChangeDate are stored as Generalized Time
        # (yyyyMMddHHmmss.ffffff±mmm). ManagementDateTimeConverter knows how to
        # parse that shape; on failure (unexpected format), fall back to the
        # raw string so it stays visible to the auditor rather than $null.
        $fnParseDate = {
            Param([string]$sRaw)
            if (-not $sRaw) { return $null }
            try   { [System.Management.ManagementDateTimeConverter]::ToDateTime($sRaw) }
            catch { $sRaw }
        }

        [PSCustomObject][ordered]@{
            Id           = $sGuid
            Name         = $sName
            Description  = Get-DEStringProperty $oDE 'msWMI-Parm1'
            Author       = Get-DEStringProperty $oDE 'msWMI-Author'
            CreationDate = & $fnParseDate (Get-DEStringProperty $oDE 'msWMI-CreationDate')
            ChangeDate   = & $fnParseDate (Get-DEStringProperty $oDE 'msWMI-ChangeDate')
            Queries      = @($aQueryDetails | ForEach-Object { $_.Query })
            QueryDetails = $aQueryDetails
        }
    }
}
