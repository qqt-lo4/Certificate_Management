function Add-ADObjectMemberOf {
    <#
    .SYNOPSIS
        Adds an AD object to one or more groups

    .DESCRIPTION
        Adds the specified AD object as a member of one or more AD groups.
        Validates that each target is a group before attempting the operation.

    .PARAMETER ADObject
        The AD object to add to groups.

    .PARAMETER ADGroup
        The AD group object(s) to add the object to.

    .PARAMETER Credential
        Optional PSCredential for AD authentication.

    .OUTPUTS
        None. Group memberships are modified in AD.

    .EXAMPLE
        Add-ADObjectMemberOf -ADObject $user -ADGroup $group1, $group2

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADObject,
        [Parameter(Mandatory, Position = 1)]
        [object[]]$ADGroup,
        [pscredential]$Credential
    )
    Begin {
        $aADGroups = @()
        foreach ($oADGroup in $ADGroup) {
            $aADGroupRequiredProperties = "objectclass"
            if (-not (Test-ContainsArray $oADGroup.PSObject.Properties.Name $aADGroupRequiredProperties)) {
                Add-ADObjectProperties $oADGroup $aADGroupRequiredProperties | Out-Null
            }
            if ($oADGroup.objectclass.ToString() -ne "group") {
                throw [System.ArgumentOutOfRangeException] "`$ADGroup is not a group"
            }
            $aADGroups += $oADGroup
        }
    }
    Process {
        try {
            if ($Credential) {
                foreach ($oADGroup in $aADGroups) {
                    Add-ADGroupMember -NewMember $ADObject -ADGroup $oADGroup -Credential $Credential
                }    
            } else {
                foreach ($oADGroup in $aADGroups) {
                    Add-ADGroupMember -NewMember $ADObject -ADGroup $oADGroup
                }    
            }
        } catch {
            Write-Host "An error occured: $($_.Exception.InnerException.Message.ToString().Trim())" -ForegroundColor Red
        }
    }
}