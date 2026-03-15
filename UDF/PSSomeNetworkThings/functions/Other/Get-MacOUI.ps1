# Global variable for OUI database cache
$global:OUICache = @{
    Database = $null
    DatabasePath = $null
    LastLoaded = $null
}

function Get-MacOUI {
    <#
    .SYNOPSIS
        Gets OUI (Organizationally Unique Identifier) information for a MAC address from the IEEE database

    .DESCRIPTION
        Takes a MAC address and returns the associated manufacturer information
        using the official IEEE OUI database. Optimized for multiple calls with
        in-memory caching.

    .PARAMETER MacAddress
        The MAC address to look up (accepted formats: XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, XXXXXXXXXXXX).

    .PARAMETER UpdateDatabase
        Force an update of the local OUI database from IEEE.

    .PARAMETER DatabasePath
        Path to the local OUI database file (default: $env:TEMP\ieee-oui.txt).

    .PARAMETER Timeout
        Timeout in seconds for web requests (default: 30).

    .PARAMETER ClearCache
        Clear the in-memory cache and force a database reload.

    .OUTPUTS
        [PSCustomObject]. OUI information with Vendor, VendorAddress, OUI, RegistryDate, etc.

    .EXAMPLE
        Get-MacOUI -MacAddress "00:1B:44:11:3A:B7"

    .EXAMPLE
        Get-MacOUI -MacAddress "001b44113ab7" -UpdateDatabase

    .EXAMPLE
        "AA:BB:CC:DD:EE:FF", "001122334455" | Get-MacOUI

    .EXAMPLE
        $macs = @("00:1B:44:11:3A:B7", "00:50:C2:12:34:56", "08:00:27:AA:BB:CC")
        $macs | Get-MacOUI

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [string[]]$MacAddress,
        
        [Parameter(Mandatory = $false)]
        [switch]$UpdateDatabase,
        
        [Parameter(Mandatory = $false)]
        [string]$DatabasePath = "$env:TEMP\ieee-oui.txt",
        
        [Parameter(Mandatory = $false)]
        [int]$Timeout = 30,
        
        [Parameter(Mandatory = $false)]
        [switch]$ClearCache
    )
    
    begin {
        # IEEE database URLs
        $ieeeOuiUrl = "https://standards-oui.ieee.org/oui/oui.txt"
        $ieeeBackupUrl = "http://standards-oui.ieee.org/oui.txt"
        
        # Optimized function to validate and normalize the MAC address
        function Format-MacAddress {
            param([string]$Mac)
            
            # Faster regex for validation and extraction
            if ($Mac -match '^([0-9A-Fa-f]{2})[:\-]?([0-9A-Fa-f]{2})[:\-]?([0-9A-Fa-f]{2})[:\-]?([0-9A-Fa-f]{2})[:\-]?([0-9A-Fa-f]{2})[:\-]?([0-9A-Fa-f]{2})$') {
                # Build the OUI directly in IEEE format
                return "$($matches[1].ToUpper())-$($matches[2].ToUpper())-$($matches[3].ToUpper())"
            }
            
            # Fallback for non-standard formats
            $cleanMac = $Mac -replace '[^0-9A-Fa-f]', ''
            
            if ($cleanMac.Length -ne 12) {
                throw "Invalid MAC address: $Mac. The address must contain 12 hexadecimal characters."
            }
            
            if ($cleanMac -notmatch '^[0-9A-Fa-f]{12}$') {
                throw "Invalid MAC address: $Mac. The address must contain only hexadecimal characters."
            }
            
            $oui = $cleanMac.Substring(0, 6).ToUpper()
            return "$($oui.Substring(0,2))-$($oui.Substring(2,2))-$($oui.Substring(4,2))"
        }
        
        # Function to download the IEEE database
        function Update-OUIDatabase {
            param([string]$Path, [int]$TimeoutSec)
            
            Write-Progress "Downloading IEEE OUI database..."
            
            try {
                # Try the main HTTPS URL
                $webRequest = @{
                    Uri = $ieeeOuiUrl
                    OutFile = $Path
                    TimeoutSec = $TimeoutSec
                    UserAgent = 'PowerShell-IEEE-OUI-Client/1.0'
                    ErrorAction = 'Stop'
                }
                
                Invoke-WebRequest @webRequest
                Write-Progress "Database downloaded successfully from $ieeeOuiUrl" -Completed
            }
            catch {
                Write-Warning "HTTPS download failed, trying HTTP..."
                try {
                    # Try the fallback HTTP URL
                    $webRequest.Uri = $ieeeBackupUrl
                    Invoke-WebRequest @webRequest
                    Write-Verbose "Database downloaded successfully from $ieeeBackupUrl"
                }
                catch {
                    throw "Unable to download the IEEE database: $($_.Exception.Message)"
                }
            }
        }
        
        # Optimized function to parse the OUI database
        function Parse-OUIDatabase {
            param([string]$Path)
            
            Write-Progress "Optimized parsing of the OUI database..."
            $ouiHash = @{}
            
            if (-not (Test-Path $Path)) {
                throw "OUI database file not found: $Path"
            }
            
            # Read all at once with StringBuilder for performance
            $content = [System.IO.File]::ReadAllLines($Path)
            $currentOUI = $null
            $currentVendor = $null
            $addressBuilder = New-Object System.Text.StringBuilder
            
            foreach ($line in $content) {
                # Optimized OUI line with compiled regex
                if ($line -match '^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$') {
                    # Save the previous entry if it exists
                    if ($currentOUI -and $currentVendor) {
                        $ouiHash[$currentOUI] = @{
                            Vendor = $currentVendor
                            Address = $addressBuilder.ToString()
                        }
                    }
                    
                    # New entry
                    $currentOUI = $matches[1]
                    $currentVendor = $matches[2].Trim()
                    $addressBuilder.Clear() | Out-Null
                }
                # Optimized address line
                elseif ($line -match '^\s+(.+)$' -and $currentOUI) {
                    $addressLine = $matches[1].Trim()
                    if ($addressLine -and $addressLine -ne $currentVendor) {
                        if ($addressBuilder.Length -gt 0) {
                            $addressBuilder.Append(", ") | Out-Null
                        }
                        $addressBuilder.Append($addressLine) | Out-Null
                    }
                }
                # Empty line - no need to reset, handled by the next OUI entry
            }
            
            # Add the last entry
            if ($currentOUI -and $currentVendor) {
                $ouiHash[$currentOUI] = @{
                    Vendor = $currentVendor
                    Address = $addressBuilder.ToString()
                }
            }
            
            Write-Progress "Database parsed: $($ouiHash.Count) OUI entries" -Completed
            return $ouiHash
        }
        
        # Function to load or use the cache
        function Get-CachedOUIDatabase {
            param([string]$DatabasePath, [bool]$ForceUpdate, [int]$TimeoutSec)
            
            # Clear cache if requested
            if ($ClearCache) {
                Write-Verbose "Clearing OUI cache"
                $global:OUICache.Database = $null
                $global:OUICache.DatabasePath = $null
                $global:OUICache.LastLoaded = $null
            }
            
            # Check if we can use the cache
            $canUseCache = $false
            if ($global:OUICache.Database -and 
                $global:OUICache.DatabasePath -eq $DatabasePath -and
                $global:OUICache.LastLoaded) {
                
                # Check that the file has not changed
                if (Test-Path $DatabasePath) {
                    $fileLastWrite = (Get-Item $DatabasePath).LastWriteTime
                    if ($fileLastWrite -le $global:OUICache.LastLoaded) {
                        $canUseCache = $true
                        Write-Verbose "Using in-memory OUI cache"
                    }
                }
            }
            
            if ($canUseCache -and -not $ForceUpdate) {
                return $global:OUICache.Database
            }
            
            # Handle database update/download
            $needUpdate = $ForceUpdate
            
            if (Test-Path $DatabasePath) {
                $dbAge = (Get-Date) - (Get-Item $DatabasePath).LastWriteTime
                if ($dbAge.TotalDays -gt 30) {
                    Write-Verbose "OUI database is old ($([math]::Round($dbAge.TotalDays)) days)"
                    if (-not $ForceUpdate) {
                        Write-Warning "The local OUI database is $([math]::Round($dbAge.TotalDays)) days old. Use -UpdateDatabase to update it."
                    }
                }
            } else {
                Write-Verbose "OUI database not found, download required"
                $needUpdate = $true
            }
            
            # Download/update if needed
            if ($needUpdate) {
                try {
                    Update-OUIDatabase -Path $DatabasePath -TimeoutSec $TimeoutSec
                }
                catch {
                    if (-not (Test-Path $DatabasePath)) {
                        throw "Unable to download the IEEE database and no local database available: $($_.Exception.Message)"
                    }
                    Write-Warning "Update failed, using existing local database: $($_.Exception.Message)"
                }
            }
            
            # Load and cache
            Write-Verbose "Loading OUI database into cache..."
            $database = Parse-OUIDatabase -Path $DatabasePath
            
            # Update the global cache
            $global:OUICache.Database = $database
            $global:OUICache.DatabasePath = $DatabasePath
            $global:OUICache.LastLoaded = Get-Date
            
            Write-Verbose "OUI database cached: $($database.Count) entries"
            return $database
        }
        
        # Load the database (with cache)
        try {
            $ouiDatabase = Get-CachedOUIDatabase -DatabasePath $DatabasePath -ForceUpdate $UpdateDatabase -TimeoutSec $Timeout
        }
        catch {
            throw "Error loading the OUI database: $($_.Exception.Message)"
        }
        
        # Get the file date for all results
        $registryDate = if (Test-Path $DatabasePath) {
            (Get-Item $DatabasePath).LastWriteTime.ToString("yyyy-MM-dd")
        } else {
            $null
        }
    }
    
    process {
        foreach ($Mac in $MacAddress) {
            try {
                Write-Verbose "Processing MAC address: $Mac"
                
                # Format and validate the MAC address
                $ouiFormatted = Format-MacAddress -Mac $Mac
                Write-Verbose "IEEE formatted OUI: $ouiFormatted"
                
                # Create the result object
                $resultProperties = [ordered]@{
                    PSTypeName = 'MacAddress'
                    OriginalAddress = $Mac
                    OUI = $ouiFormatted
                    Vendor = $null
                    VendorAddress = $null
                    RegistryDate = $registryDate
                    Source = "IEEE Database"
                    #Success = $false
                    #Error = $null
                }
                
                # Optimized lookup in the IEEE database
                if ($ouiDatabase.ContainsKey($ouiFormatted)) {
                    $ouiInfo = $ouiDatabase[$ouiFormatted]
                    $resultProperties.Vendor = $ouiInfo.Vendor
                    $resultProperties.VendorAddress = $ouiInfo.Address
                    #$resultProperties.Success = $true
                    Write-Verbose "OUI found: $($ouiInfo.Vendor)"
                }
                else {
                    $resultProperties.Vendor = "Unassigned or private OUI"
                    $resultProperties.Error = "OUI not found in IEEE database"
                    Write-Verbose "OUI not found in IEEE database"
                }
                
                # Create and return the object
                $result = [PSCustomObject]$resultProperties
                Write-Output $result
                
            }
            catch {
                Write-Error "Error processing $Mac : $($_.Exception.Message)"
                
                # Return an error object with PSTypeName
                $errorResult = [PSCustomObject]@{
                    PSTypeName = 'MacAddress'
                    OriginalAddress = $Mac
                    OUI = $null
                    Vendor = $null
                    VendorAddress = $null
                    RegistryDate = $registryDate
                    Source = "Error"
                    Success = $false
                    Error = $_.Exception.Message
                }
                
                Write-Output $errorResult
            }
        }
    }
    
    end {
        # No cleanup - keep the cache for subsequent calls
        Write-Verbose "Processing complete. OUI cache kept for next calls."
    }
}

# Utility function to manage the OUI database
function Update-OUIDatabase {
    <#
    .SYNOPSIS
        Updates the local IEEE OUI database

    .DESCRIPTION
        Downloads the latest OUI database from IEEE and refreshes the in-memory cache.

    .PARAMETER DatabasePath
        Path to the database file (default: $env:TEMP\ieee-oui.txt).

    .PARAMETER Force
        Force the update even if the database is recent.

    .EXAMPLE
        Update-OUIDatabase

    .EXAMPLE
        Update-OUIDatabase -DatabasePath "C:\Data\oui.txt" -Force

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$DatabasePath = "$env:TEMP\ieee-oui.txt",
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    try {
        # Use Get-MacOUI with -UpdateDatabase and -ClearCache
        $null = Get-MacOUI -MacAddress "00:00:00:00:00:00" -UpdateDatabase -ClearCache -DatabasePath $DatabasePath -ErrorAction SilentlyContinue
        
        if (Test-Path $DatabasePath) {
            $dbInfo = Get-Item $DatabasePath
            Write-Host "OUI database updated successfully!" -ForegroundColor Green
            Write-Host "File: $DatabasePath" -ForegroundColor Gray
            Write-Host "Size: $([math]::Round($dbInfo.Length/1MB, 2)) MB" -ForegroundColor Gray
            Write-Host "Date: $($dbInfo.LastWriteTime)" -ForegroundColor Gray
            Write-Host "In-memory cache reloaded." -ForegroundColor Gray
        }
    }
    catch {
        Write-Error "Error during update: $($_.Exception.Message)"
    }
}

# Function to manage the cache
function Clear-OUICache {
    <#
    .SYNOPSIS
        Clears the in-memory OUI cache

    .DESCRIPTION
        Forces a reload of the OUI database on the next Get-MacOUI call.

    .EXAMPLE
        Clear-OUICache

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    
    $global:OUICache.Database = $null
    $global:OUICache.DatabasePath = $null
    $global:OUICache.LastLoaded = $null
    Write-Host "OUI cache cleared." -ForegroundColor Green
}

# Optimized usage examples:

<#
# Example 1: First call (loads the database into cache)
$mac1 = Get-MacOUI -MacAddress "00:1B:44:11:3A:B7"  # ~2-3 seconds

# Example 2: Subsequent calls (uses cache)
$mac2 = Get-MacOUI -MacAddress "00:50:C2:12:34:56"  # ~100ms
$mac3 = Get-MacOUI -MacAddress "08:00:27:AA:BB:CC"  # ~100ms

# Example 3: Optimized batch processing
Measure-Command {
    $macs = @("00:1B:44:11:3A:B7", "00:50:C2:12:34:56", "08:00:27:AA:BB:CC", "AC:DE:48:12:34:56")
    $results = $macs | Get-MacOUI
}  # First batch: ~3 seconds, subsequent batches: ~500ms

# Example 4: Optimized pipeline
"00:1B:44:11:3A:B7", "00:50:C2:12:34:56", "08:00:27:AA:BB:CC" | Get-MacOUI

# Example 5: Clear cache if needed
Clear-OUICache

# Example 6: Force update with cache clearing
Get-MacOUI -MacAddress "00:1B:44:11:3A:B7" -UpdateDatabase -ClearCache

# Example 7: High volume processing
1..1000 | ForEach-Object { 
    $randomMac = "{0:X2}:{1:X2}:{2:X2}:{3:X2}:{4:X2}:{5:X2}" -f (Get-Random -Min 0 -Max 255),(Get-Random -Min 0 -Max 255),(Get-Random -Min 0 -Max 255),(Get-Random -Min 0 -Max 255),(Get-Random -Min 0 -Max 255),(Get-Random -Min 0 -Max 255)
    Get-MacOUI -MacAddress $randomMac
} | Group-Object Vendor | Sort-Object Count -Descending
#>