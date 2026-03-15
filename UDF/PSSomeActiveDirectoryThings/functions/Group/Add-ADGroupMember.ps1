function Add-ADGroupMember {
    <#
    .SYNOPSIS
        Adds one or more members to an AD group

    .DESCRIPTION
        Adds AD objects as members of a group by modifying the group's member
        attribute via DirectoryEntry. Supports single or multiple members
        and optional credentials.

    .PARAMETER ADGroup
        The AD group object to add members to.

    .PARAMETER NewMember
        The AD object(s) to add as members. Alias: ADObject.

    .PARAMETER Credential
        Optional PSCredential for authentication.

    .OUTPUTS
        None. The group membership is modified in AD.

    .EXAMPLE
        Add-ADGroupMember -ADGroup $group -NewMember $user

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADGroup,
        [Parameter(Mandatory, Position = 1)]
        [Alias("ADObject")]
        [object]$NewMember,
        [pscredential]$Credential
    )
    Begin {
        $aNewMemberRequiredProperties = "distinguishedname"
        if (-not (Test-ContainsArray $NewMember.PSObject.Properties.Name $aNewMemberRequiredProperties)) {
            Add-ADObjectProperties $NewMember $aNewMemberRequiredProperties | Out-Null
        }
        $aADGroupRequiredProperties = "objectclass"
        if (-not (Test-ContainsArray $ADGroup.PSObject.Properties.Name $aADGroupRequiredProperties)) {
            Add-ADObjectProperties $ADGroup $aADGroupRequiredProperties | Out-Null
        }
        if ($ADGroup.objectclass.ToString() -ne "group") {
            throw [System.ArgumentOutOfRangeException] "`$ADGroup is not a group"
        }
        $oDirectoryEntry = if ($Credential) {
            Get-DirectoryEntry -Path $ADGroup.adspath -Credential $Credential
        } else {
            Get-DirectoryEntry -Path $ADGroup.adspath
        }
    }
    Process {
        try {
            if ($NewMember -is [array]) {
                foreach ($oNewMember in $NewMember) {
                    $oDirectoryEntry.Properties["member"].Add($oNewMember.distinguishedname) | Out-Null
                }
            } else {
                $oDirectoryEntry.Properties["member"].Add($NewMember.distinguishedname) | Out-Null
            }
            $oDirectoryEntry.CommitChanges()
        } catch {
            Write-Host "An error occured: $($_.Exception.InnerException.Message.ToString().Trim())" -ForegroundColor Red
        }
    }
}