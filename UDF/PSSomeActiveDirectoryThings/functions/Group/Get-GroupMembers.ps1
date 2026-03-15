function Get-GroupMembers {
    <#
    .SYNOPSIS
        Retrieves members of an AD group with optional recursion

    .DESCRIPTION
        Returns the members of an AD group object. Supports recursive enumeration
        of nested groups, tracking the inheritance path. Each member gets an
        InheritedFrom property showing the group chain.

    .PARAMETER ADObject
        The AD group object to enumerate members from. Accepts pipeline input.

    .PARAMETER ADObjectProperties
        Properties to load for each member.

    .PARAMETER AdditionalProperties
        Extra properties to add to each member.

    .PARAMETER Recurse
        If specified, recursively enumerates members of nested groups.

    .OUTPUTS
        Custom AD object[]. The group members with optional InheritedFrom chain.

    .EXAMPLE
        $group = Get-ADGroup -Identity "IT-Team"
        Get-GroupMembers -ADObject $group -Recurse

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
        [object]$ADObject,
        [string[]]$ADObjectProperties,
        [string[]]$AdditionalProperties,
        [switch]$Recurse
    )
    Begin {

        function Get-GroupMembers_inter {
            Param(
                [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
                [object]$ADObject,
                [string[]]$ADObjectProperties,
                [string[]]$AdditionalProperties,
                [object[]]$InheritedFrom = @(),
                [switch]$Recurse
            )
            Begin {
                if (-not (Test-ContainsArray $ADObject.PSObject.Properties.Name "objectclass")) {
                    Add-ADObjectProperties $ADObject "objectclass" | Out-Null
                }
                if ($ADObject.objectclass.ToString() -ne "group") {
                    throw [System.ArgumentException] "`$ADObject is not a group"
                }
                $aResult = @()
            }
            Process {
                if ($ADObject.member -ne $null) {
                    $hGetADDNObjectArgs = @{
                        DN = $ADObject.member
                    }
                    if ($ADObjectProperties) {
                        $hGetADDNObjectArgs.Properties = $ADObjectProperties
                    }
                    if ($AdditionalProperties) {
                        $hGetADDNObjectArgs.AdditionalProperties = $AdditionalProperties
                    }
                    $aGroupContentResult = Get-ADDNObject @hGetADDNObjectArgs
                    if ($Recurse) {
                        foreach ($item in $aGroupContentResult) {
                            $aInheritedFrom = $InheritedFrom + $ADObject.name
                            $item | Add-Member -NotePropertyName "InheritedFrom" -NotePropertyValue $aInheritedFrom
                            if ($item.objectclass.ToString() -eq "group") {
                                Get-GroupMembers_inter -ADObject $item -ADObjectProperties $ADObjectProperties -AdditionalProperties $AdditionalProperties -InheritedFrom $aInheritedFrom -Recurse
                            }
                        }
                    }
                    $aResult += $aGroupContentResult
                }
            }
            End {
                return $aResult 
            }
        }

        if (-not (Test-ContainsArray $ADObject.PSObject.Properties.Name "objectclass")) {
            Add-ADObjectProperties $ADObject "objectclass" | Out-Null
        }
        if ($ADObject.objectclass.ToString() -ne "group") {
            throw [System.ArgumentException] "`$ADObject is not a group"
        }
    }
    Process {
        $aResult = Get-GroupMembers_inter @PSBoundParameters
        foreach ($item in $aResult) {
            $item.InheritedFrom = $item.InheritedFrom -join " > "
        }
    }
    End {
        return $aResult 
    }
}
