function Invoke-RDAPQuery {
    <#
    .SYNOPSIS
        Performs an RDAP (Registration Data Access Protocol) query

    .DESCRIPTION
        Queries RDAP servers to retrieve registration information for domains,
        IP addresses, and ASNs. Supports automatic RDAP server discovery via
        IANA bootstrap registries, with fallback to known servers.
        Private/documented IPs are detected and handled locally.

    .PARAMETER Query
        The object to query (domain, IP address, or ASN).

    .PARAMETER Type
        Query type: Domain, IP, or ASN (auto-detected if omitted).

    .PARAMETER Server
        Specific RDAP server URL to use (optional).

    .PARAMETER UserAgent
        User-Agent string for HTTP requests (default: "PowerShell-RDAP-Client/1.0").

    .PARAMETER TimeoutSeconds
        HTTP request timeout in seconds (default: 30).

    .PARAMETER IncludeRaw
        Include the raw JSON response in the result.

    .OUTPUTS
        [PSCustomObject]. RDAP response with ObjectClassName, Handle, Status, Events, Entities, etc.

    .EXAMPLE
        Invoke-RDAPQuery -Query "example.com"

    .EXAMPLE
        Invoke-RDAPQuery -Query "8.8.8.8"

    .EXAMPLE
        Invoke-RDAPQuery -Query "15169"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Query,
        
        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet("Domain", "IP", "ASN")]
        [string]$Type,
        
        [Parameter(Mandatory = $false)]
        [string]$Server,
        
        [Parameter(Mandatory = $false)]
        [string]$UserAgent = "PowerShell-RDAP-Client/1.0",
        
        [Parameter(Mandatory = $false)]
        [int]$TimeoutSeconds = 30,
        
        [Parameter(Mandatory = $false)]
        [switch]$IncludeRaw
    )
    
    # IANA bootstrap URLs for automatic discovery
    $BootstrapUrls = @{
        "Domain" = "https://data.iana.org/rdap/dns.json"
        "IP4" = "https://data.iana.org/rdap/ipv4.json"
        "IP6" = "https://data.iana.org/rdap/ipv6.json"
        "ASN" = "https://data.iana.org/rdap/asn.json"
    }
    
    # Universal bootstrap service (recommended alternative)
    $UniversalBootstrap = "https://rdap.org"
    
    function Get-QueryType {
        param($Query)
        
        # Use existing regex functions to detect the type
        $ipRegex = Get-IPRegex -FullLine
        $dnsRegex = Get-DNSRegex -FullLine
        
        # Test for ASN (format AS12345 or just 12345)
        if ($Query -match '^(AS)?(\d+)$') {
            return "ASN"
        }
        
        # Test for IP address
        if ($Query -match $ipRegex) {
            return "IP"
        }
        
        # Test for domain name
        if ($Query -match $dnsRegex) {
            return "Domain"
        }
        
        # Default, treat as a domain
        Write-Warning "Type not detected for '$Query', treating as domain"
        return "Domain"
    }
    
    # Auto-detect the type if not specified
    if (-not $Type) {
        $Type = Get-QueryType -Query $Query
        Write-Verbose "Auto-detected type: $Type"
    }
    
    if ($Type -eq "IP") {
        $privateCheck = Test-PrivateOrDocumentedIP -IPAddress $Query
        
        if ($privateCheck.IsPrivateOrDocumented) {
            # Calculate network attributes for compatibility with standard RDAP responses
            $networkParts = $privateCheck.Range -split '/'
            $networkIP = $networkParts[0]
            $prefixLength = [int]$networkParts[1]
            
            # Calculate StartAddress and EndAddress based on IP type
            if ($privateCheck.IPVersion -eq "IPv4") {
                # Use IPv4 network function
                try {
                    $networkObj = New-Networkv4Object -InputString $privateCheck.Range
                    $startAddress = $networkObj.Network.ToString()
                    $endAddress = $networkObj.Broadcast.ToString()
                    $cidrArray = @(@{
                        v4prefix = $startAddress
                        length = $networkObj.Mask.GetMaskLength()
                    })
                } catch {
                    # Fallback in case of error
                    $startAddress = $networkIP
                    $endAddress = $networkIP
                    $cidrArray = @(@{
                        v4prefix = $networkIP
                        length = $prefixLength
                    })
                }
            } else {
                # IPv6
                try {
                    $networkObj = New-Networkv6Object -InputString $privateCheck.Range
                    $startAddress = $networkObj.First.ToString()
                    $endAddress = $networkObj.Last.ToString()
                    $cidrArray = @(@{
                        v6prefix = $networkObj.Network.ToString()
                        length = $networkObj.PrefixLength
                    })
                } catch {
                    # Fallback in case of error
                    $startAddress = $networkIP
                    $endAddress = $networkIP
                    $cidrArray = @(@{
                        v6prefix = $networkIP
                        length = $prefixLength
                    })
                }
            }
            
            # Return an informative object instead of an error
            return [PSCustomObject]@{
                PSTypeName = 'RDAP Response'
                ObjectClassName = "ip network"
                Handle = $null
                Status = @("private")
                Query = $Query
                StartAddress = $startAddress
                EndAddress = $endAddress
                IPVersion = if ($privateCheck.IPVersion -eq "IPv4") { "v4" } else { "v6" }
                Name = $privateCheck.Description
                Type = "PRIVATE/DOCUMENTED"
                Country = $null
                ParentHandle = $null
                CIDR = $cidrArray
                Range = $privateCheck.Range
                Events = @()
                Entities = @()
                Networks = @()
                Nameservers = @()
                Links = $null
                Port43 = $null
                Raw = $null
            }
        }
        
        Write-Verbose "Public IP address detected, continuing RDAP query..."
    }

    # Cache for bootstrap registries (avoid downloading them on each query)
    if (-not $global:RDAPBootstrapCache) {
        $global:RDAPBootstrapCache = @{}
    }
    
    function Get-BootstrapRegistry {
        param($Type)
        
        $cacheKey = "Bootstrap_$Type"
        $cacheExpiry = (Get-Date).AddHours(-1) # Cache for 1 hour
        
        # Check the cache
        if ($global:RDAPBootstrapCache[$cacheKey] -and 
            $global:RDAPBootstrapCache[$cacheKey].Timestamp -gt $cacheExpiry) {
            return $global:RDAPBootstrapCache[$cacheKey].Data
        }
        
        try {
            $bootstrapUrl = switch ($Type) {
                "Domain" { $BootstrapUrls["Domain"] }
                "IP" { if ($Query -match ":") { $BootstrapUrls["IP6"] } else { $BootstrapUrls["IP4"] } }
                "ASN" { $BootstrapUrls["ASN"] }
                default { $null }
            }
            
            if ($bootstrapUrl) {
                Write-Verbose "Downloading bootstrap registry: $bootstrapUrl"
                $registry = Invoke-RestMethod -Uri $bootstrapUrl -TimeoutSec 10 -ErrorAction Stop
                
                # Store in cache
                $global:RDAPBootstrapCache[$cacheKey] = @{
                    Data = $registry
                    Timestamp = Get-Date
                }
                
                return $registry
            }
        } catch {
            Write-Verbose "Unable to download bootstrap registry: $($_.Exception.Message)"
        }
        
        return $null
    }
    
    function Find-RDAPServerInBootstrap {
        param($Query, $Type, $Registry)
        
        if (-not $Registry -or -not $Registry.services) {
            return $null
        }
        
        foreach ($service in $Registry.services) {
            $entries = $service[0]
            $servers = $service[1]
            
            switch ($Type) {
                "Domain" {
                    $tld = "." + ($Query -split '\.')[-1].ToLower()
                    if ($entries -contains $tld) {
                        return $servers[0].TrimEnd('/')
                    }
                }
                "IP" {
                    # Check if the IP is in one of the CIDR blocks
                    foreach ($entry in $entries) {
                        if (Test-IPInNetwork -IPAddress $Query -Network $entry) {
                            return $servers[0].TrimEnd('/')
                        }
                    }
                }
                "ASN" {
                    $asnNumber = [int]($Query -replace '^AS', '')
                    foreach ($entry in $entries) {
                        if ($entry -match '^(\d+)-(\d+)$') {
                            $start = [int]$matches[1]
                            $end = [int]$matches[2]
                            if ($asnNumber -ge $start -and $asnNumber -le $end) {
                                return $servers[0].TrimEnd('/')
                            }
                        }
                    }
                }
            }
        }
        
        return $null
    }

    function Get-RDAPServer {
        param($Query, $Type)
        
        if ($Server) {
            return $Server.TrimEnd('/')
        }
        
        # Option 1: Use the universal bootstrap service (recommended)
        if ($env:RDAP_USE_UNIVERSAL_BOOTSTRAP -ne 'false') {
            Write-Verbose "Using universal bootstrap service: $UniversalBootstrap"
            return $UniversalBootstrap.TrimEnd('/')
        }
        
        # Option 2: Discovery via IANA registries
        $registry = Get-BootstrapRegistry -Type $Type
        if ($registry) {
            $discoveredServer = Find-RDAPServerInBootstrap -Query $Query -Type $Type -Registry $registry
            if ($discoveredServer) {
                Write-Verbose "Server discovered via bootstrap: $discoveredServer"
                return $discoveredServer
            }
        }
        
        # Option 3: Fallback to known servers
        Write-Verbose "Using fallback servers"
        switch ($Type) {
            "Domain" { 
                $tld = ($Query -split '\.')[-1].ToLower()
                switch ($tld) {
                    "com" { return "https://rdap.verisign.com/com/v1" }
                    "net" { return "https://rdap.verisign.com/net/v1" }
                    "org" { return "https://rdap.pir.org" }
                    "fr" { return "https://rdap.nic.fr" }
                    "uk" { return "https://rdap.nominet.uk" }
                    "de" { return "https://rdap.denic.de" }
                    "it" { return "https://rdap.nic.it" }
                    "nl" { return "https://rdap.dns.nl" }
                    "eu" { return "https://rdap.eu" }
                    "info" { return "https://rdap.afilias.net/rdap/afilias" }
                    "biz" { return "https://rdap.afilias.net/rdap/afilias" }
                    default { return "https://rdap.verisign.com/com/v1" }
                }
            }
            "IP" { return "https://rdap.arin.net/registry" }
            "ASN" { return "https://rdap.arin.net/registry" }
            default { throw "Unsupported query type: $Type" }
        }
    }
    
    function Build-RDAPUrl {
        param($Server, $Type, $Query)
        
        $baseUrl = $Server.TrimEnd('/')
        
        switch ($Type) {
            "Domain" { return "$baseUrl/domain/$Query" }
            "IP" { return "$baseUrl/ip/$Query" }
            "ASN" { return "$baseUrl/autnum/$Query" }
        }
    }
    
    function Parse-VCardArray {
        param($VCardArray)
        
        if (-not $VCardArray -or $VCardArray.Count -lt 2) {
            return $null
        }
        
        $vCardData = $VCardArray[1]
        $contact = [PSCustomObject]@{
            PSTypeName = 'RDAP Contact'
            Name = $null
            Organization = $null
            Email = @()
            Phone = @()
            Address = $null
            Kind = $null
        }
        
        foreach ($field in $vCardData) {
            if ($field.Count -lt 4) { continue }
            
            $fieldName = $field[0]
            $fieldParams = $field[1]
            $fieldType = $field[2]
            $fieldValue = $field[3]
            
            switch ($fieldName) {
                "fn" { 
                    $contact.Name = $fieldValue 
                }
                "org" { 
                    $contact.Organization = $fieldValue 
                }
                "email" { 
                    $contact.Email += $fieldValue 
                }
                "tel" { 
                    $phoneInfo = [PSCustomObject]@{
                        PSTypeName = 'RDAP Contact Phone'
                        Number = $fieldValue
                        Type = if ($fieldParams.type) { $fieldParams.type -join ", " } else { "Unknown" }
                    }
                    $contact.Phone += $phoneInfo
                }
                "adr" { 
                    if ($fieldParams.label) {
                        $contact.Address = $fieldParams.label -replace '\\n', "`n"
                    } elseif ($fieldValue -is [array] -and $fieldValue.Count -gt 0) {
                        $contact.Address = ($fieldValue | Where-Object { $_ -ne "" }) -join ", "
                    }
                }
                "kind" { 
                    $contact.Kind = $fieldValue 
                }
            }
        }
        
        return $contact
    }

    function Parse-RDAPResponse {
        param($Response)
        
        # Check if the response is a byte array and convert it
        if ($Response -is [array] -and $Response[0] -is [byte]) {
            Write-Verbose "Converting byte array to JSON"
            $jsonString = [System.Text.Encoding]::UTF8.GetString($Response)
            $Response = $jsonString | ConvertFrom-Json
        }
        
        # Check that the response is not empty
        if (-not $Response) {
            Write-Warning "Empty RDAP response"
            return $null
        }
        
        # Display the response in verbose mode for debugging
        Write-Verbose "ObjectClassName: $($Response.objectClassName)"
        Write-Verbose "Handle: $($Response.handle)"
        
        $result = [PSCustomObject]@{
            PSTypeName = 'RDAP Response'
            ObjectClassName = $Response.objectClassName
            Query = $Query
            Handle = $Response.handle
            Status = $Response.status
            Events = @()
            Entities = @()
            Networks = @()
            Nameservers = @()
            Links = $Response.links
            Port43 = $Response.port43
            Raw = if ($IncludeRaw) { $Response } else { $null }
        }
        
        # Parse events
        if ($Response.events -and $Response.events.Count -gt 0) {
            $result.Events = $Response.events | ForEach-Object {
                [PSCustomObject]@{
                    PSTypeName = 'RDAP Event'
                    EventAction = $_.eventAction
                    EventDate = if ($_.eventDate) { [DateTime]$_.eventDate } else { $null }
                    EventActor = $_.eventActor
                }
            }
        }
        
        # Parse entities (contacts) with automatic expansion
        if ($Response.entities -and $Response.entities.Count -gt 0) {
            $result.Entities = @()
            foreach ($entity in $Response.entities) {
                $contact = Parse-VCardArray -VCardArray $entity.vcardArray
                
                $expandedEntity = [PSCustomObject]@{
                    PSTypeName = 'RDAP Entity'
                    Handle = $entity.handle
                    Roles = $entity.roles
                    Contact = $contact
                    PublicIds = $entity.publicIds
                    ObjectClassName = $entity.objectClassName
                    Remarks = $entity.remarks
                    Links = $entity.links
                    Events = $entity.events
                    Status = $entity.status
                    Port43 = $entity.port43
                }
                
                # Process nested entities (like abuse within registrant)
                if ($entity.entities) {
                    $nestedEntities = @()
                    foreach ($nested in $entity.entities) {
                        $nestedContact = Parse-VCardArray -VCardArray $nested.vcardArray
                        $nestedEntity = [PSCustomObject]@{
                            PSTypeName = 'RDAP Entity'
                            Handle = $nested.handle
                            Roles = $nested.roles
                            Contact = $nestedContact
                            PublicIds = $nested.publicIds
                            ObjectClassName = $nested.objectClassName
                            Remarks = $nested.remarks
                            Links = $nested.links
                            Events = $nested.events
                            Status = $nested.status
                            Port43 = $nested.port43
                        }
                        $nestedEntities += $nestedEntity
                    }
                    
                    if ($nestedEntities.Count -gt 0) {
                        $expandedEntity | Add-Member -NotePropertyName "NestedEntities" -NotePropertyValue $nestedEntities
                    }
                }
                
                $result.Entities += $expandedEntity
            }
        }
        
        # Parse networks (for IPs)
        if ($Response.networks -and $Response.networks.Count -gt 0) {
            $result.Networks = $Response.networks
        }
        
        # Parse nameservers (for domains)
        if ($Response.nameservers -and $Response.nameservers.Count -gt 0) {
            $result.Nameservers = $Response.nameservers | ForEach-Object {
                [PSCustomObject]@{
                    PSTypeName = 'RDAP Nameserver'
                    ObjectClassName = $_.objectClassName
                    Handle = $_.handle
                    LdhName = $_.ldhName
                    UnicodeName = $_.unicodeName
                    IPAddresses = $_.ipAddresses
                    Status = $_.status
                }
            }
        }
        
        # Add type-specific properties
        switch ($Response.objectClassName) {
            "domain" {
                $result | Add-Member -NotePropertyName "LdhName" -NotePropertyValue $Response.ldhName
                $result | Add-Member -NotePropertyName "UnicodeName" -NotePropertyValue $Response.unicodeName
                $result | Add-Member -NotePropertyName "Variants" -NotePropertyValue $Response.variants
                $result | Add-Member -NotePropertyName "SecureDNS" -NotePropertyValue $Response.secureDNS
            }
            { $_ -eq "ip network" -or $_ -eq "ip" } {
                $result | Add-Member -NotePropertyName "StartAddress" -NotePropertyValue $Response.startAddress
                $result | Add-Member -NotePropertyName "EndAddress" -NotePropertyValue $Response.endAddress
                $result | Add-Member -NotePropertyName "IPVersion" -NotePropertyValue $Response.ipVersion
                $result | Add-Member -NotePropertyName "Name" -NotePropertyValue $Response.name
                $result | Add-Member -NotePropertyName "Type" -NotePropertyValue $Response.type
                $result | Add-Member -NotePropertyName "Country" -NotePropertyValue $Response.country
                $result | Add-Member -NotePropertyName "ParentHandle" -NotePropertyValue $Response.parentHandle
                $result | Add-Member -NotePropertyName "CIDR" -NotePropertyValue $Response.cidr0_cidrs
            }
            "autnum" {
                $result | Add-Member -NotePropertyName "StartAutnum" -NotePropertyValue $Response.startAutnum
                $result | Add-Member -NotePropertyName "EndAutnum" -NotePropertyValue $Response.endAutnum
                $result | Add-Member -NotePropertyName "Name" -NotePropertyValue $Response.name
                $result | Add-Member -NotePropertyName "Type" -NotePropertyValue $Response.type
                $result | Add-Member -NotePropertyName "Country" -NotePropertyValue $Response.country
            }
        }
        
        return $result
    }
    
    try {
        # Determine the RDAP server to use
        $rdapServer = Get-RDAPServer -Query $Query -Type $Type
        Write-Verbose "Using RDAP server: $rdapServer"
        
        # If using the universal bootstrap service, build the URL differently
        if ($rdapServer -eq $UniversalBootstrap.TrimEnd('/')) {
            $rdapUrl = Build-RDAPUrl -Server $rdapServer -Type $Type -Query $Query
            
            # The bootstrap service may return a 302 redirect
            $headers = @{
                "User-Agent" = $UserAgent
                "Accept" = "application/rdap+json, application/json"
            }
            
            # Use Invoke-RestMethod directly which handles redirections automatically
            $rdapResponse = Invoke-RestMethod -Uri $rdapUrl -Headers $headers -TimeoutSec $TimeoutSeconds -MaximumRedirection 5 -ErrorAction Stop
        } else {
            # Build the query URL for direct server
            $rdapUrl = Build-RDAPUrl -Server $rdapServer -Type $Type -Query $Query
            Write-Verbose "URL RDAP: $rdapUrl"
            
            # Perform the HTTP request
            $headers = @{
                "User-Agent" = $UserAgent
                "Accept" = "application/rdap+json, application/json"
            }
            
            $rdapResponse = Invoke-RestMethod -Uri $rdapUrl -Headers $headers -TimeoutSec $TimeoutSeconds -ErrorAction Stop
        }
        
        # Parse and return the response
        return Parse-RDAPResponse -Response $rdapResponse
        
    } catch {
        $errorMessage = "Error during RDAP query: $($_.Exception.Message)"
        
        if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode
            $errorMessage += " (Code HTTP: $statusCode)"
        }
        
        Write-Error $errorMessage
        return $null
    }
}