function Convert-ADUserToUserPrincipal {
    <#
    .SYNOPSIS
        Converts an AD user object to a UserPrincipal object

    .DESCRIPTION
        Creates a System.DirectoryServices.AccountManagement.UserPrincipal object from
        an AD user object by establishing a PrincipalContext and looking up the user
        by distinguished name. Supports optional domain and credential parameters.

    .PARAMETER ADObject
        The AD user object to convert.

    .PARAMETER Domain
        The domain to connect to. Accepts a domain name or a DN string containing DC components.
        If omitted, the domain is extracted from the AD object's path.

    .PARAMETER Credential
        Optional credentials for authenticating to the domain.

    .OUTPUTS
        [System.DirectoryServices.AccountManagement.UserPrincipal]. The UserPrincipal object.

    .EXAMPLE
        $principal = Convert-ADUserToUserPrincipal -ADObject $user -Domain "corp.example.com"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADObject,
        [string]$Domain,
        [pscredential]$Credential
    )
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $aContextArgs = @()
    $aContextArgs += [System.DirectoryServices.AccountManagement.ContextType]::Domain
    if ($Domain) {
        if ($Domain -match ",DC=") {
            $aContextArgs += ConvertFrom-DN $Domain
        } else {
            $aContextArgs += $Domain
        }
    } else {
        $aContextArgs += ConvertFrom-DN $ADObject.AdditionalProperties.Path
    }
    if ($Credential) {
        $aContextArgs += $Credential.UserName
        $aContextArgs += [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password))
    }
    $oContext = New-Object "System.DirectoryServices.AccountManagement.PrincipalContext" -ArgumentList $aContextArgs
    $sDN = $ADObject.AdditionalProperties.Path.SubString($ADObject.AdditionalProperties.Path.LastIndexOf("/") + 1)
    $oUserPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($oContext, [System.DirectoryServices.AccountManagement.IdentityType]::DistinguishedName, $sDN)
    return $oUserPrincipal
}
