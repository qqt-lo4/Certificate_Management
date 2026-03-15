function Get-ADObjectClasses {
    <#
    .SYNOPSIS
        Retrieves all object class definitions from the Active Directory schema

    .DESCRIPTION
        Queries the AD schema naming context for all classSchema objects and enriches
        each class with computed properties: AttributeCount, HasSuperiors, Category
        (Structural/Abstract/Auxiliary/88 Class), and IsSystem flag.

    .PARAMETER Server
        The AD server (domain controller or domain name) to query. Defaults to the
        current user's DNS domain.

    .PARAMETER Credential
        Optional PSCredential for authenticating to the AD server.

    .OUTPUTS
        Microsoft.ActiveDirectory.Management.ADObject[]. Schema class objects sorted by Name.

    .EXAMPLE
        Get-ADObjectClasses
        # Lists all AD schema classes from the current domain

    .EXAMPLE
        Get-ADObjectClasses -Server "dc01.contoso.com" -Credential $cred

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$Server = $env:USERDNSDOMAIN,
        
        [Parameter()]
        [System.Management.Automation.PSCredential]
        $Credential
    )
    
    try {
        # Build connection parameters
        $searchParams = @{
            LDAPFilter = "(objectClass=classSchema)"
            Properties = "*"
        }

        # Add credentials if specified
        if ($Credential) {
            $searchParams["Credential"] = $Credential
            $searchParams["Server"] = $Server
        }

        # Retrieve the schema naming context
        $rootDSE = Get-ADRootDSE -Server $Server
        $schemaNamingContext = $rootDSE.schemaNamingContext

        # Search for classes in the schema
        $classes = Get-ADObject -SearchBase $schemaNamingContext @searchParams

        # Add computed properties for easier analysis
        $classes | ForEach-Object {
            if (-not $_.AttributeCount) {
                $attributeCount = ($_.systemMustContain.Count + $_.systemMayContain.Count)
                $_ | Add-Member -MemberType NoteProperty -Name "AttributeCount" -Value $attributeCount -Force
            }
            
            if (-not $_.HasSuperiors) {
                $hasSuperiors = ($null -ne $_.systemPossibleSuperiors -and $_.systemPossibleSuperiors.Count -gt 0)
                $_ | Add-Member -MemberType NoteProperty -Name "HasSuperiors" -Value $hasSuperiors -Force
            }
            
            if (-not $_.Category) {
                $category = switch ($_.objectClassCategory) {
                    "0" {"Structural"}
                    "1" {"Abstract"}
                    "2" {"Auxiliary"}
                    "3" {"88 Class"}
                    default {"Unknown"}
                }
                $_ | Add-Member -MemberType NoteProperty -Name "Category" -Value $category -Force
            }
            
            if (-not $_.IsSystem) {
                $isSystem = ($_.systemFlags -band 0x10) -eq 0x10
                $_ | Add-Member -MemberType NoteProperty -Name "IsSystem" -Value $isSystem -Force
            }
        }

        return $classes | Sort-Object Name
    }
    catch {
        Write-Error "Error retrieving AD object classes: $_"
        return $null
    }
}