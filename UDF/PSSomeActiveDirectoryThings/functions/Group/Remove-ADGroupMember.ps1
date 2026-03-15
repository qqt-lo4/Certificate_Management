function Remove-ADGroupMember {
    <#
    .SYNOPSIS
        Removes a member from an AD group

    .DESCRIPTION
        Removes an AD object from a group's member attribute via DirectoryEntry.
        Automatically converts GC:// paths to LDAP:// for write operations.

    .PARAMETER ADGroup
        The AD group object to remove the member from.

    .PARAMETER Member
        The AD object to remove from the group.

    .PARAMETER Credential
        Optional PSCredential for authentication.

    .OUTPUTS
        None. The group membership is modified in AD.

    .EXAMPLE
        Remove-ADGroupMember -ADGroup $group -Member $user

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADGroup,
        [Parameter(Mandatory, Position = 1)]
        [object]$Member,
        [pscredential]$Credential
    )
    Begin {
        $aMemberRequiredProperties = "distinguishedname"
        if (-not (Test-ContainsArray $Member.PSObject.Properties.Name $aMemberRequiredProperties)) {
            Add-ADObjectProperties $Member $aMemberRequiredProperties | Out-Null
        }
        $aADGroupRequiredProperties = "objectclass"
        if (-not (Test-ContainsArray $ADGroup.PSObject.Properties.Name $aADGroupRequiredProperties)) {
            Add-ADObjectProperties $ADGroup $aADGroupRequiredProperties | Out-Null
        }
        if ($ADGroup.objectclass.ToString() -ne "group") {
            throw [System.ArgumentOutOfRangeException] "`$ADGroup is not a group"
        }
        $sPath = if ($ADGroup.adspath -like "GC://*") {
            $ADGroup.adspath.Replace("GC://", "LDAP://")
        } else {
            $ADGroup.adspath
        }
        $oDirectoryEntry = if ($Credential) {
            Get-DirectoryEntry -Path $sPath -Credential $Credential
        } else {
            Get-DirectoryEntry -Path $sPath
        }
    }
    Process {
        try {
            $oDirectoryEntry.Properties["member"].Remove($Member.distinguishedname) | Out-Null
            $oDirectoryEntry.CommitChanges()
        } catch {
            Write-Host "An error occured: $($_.Exception.InnerException.Message.ToString().Trim())" -ForegroundColor Red
        }
    }
}
