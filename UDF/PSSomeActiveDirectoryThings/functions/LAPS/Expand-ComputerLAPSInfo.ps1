function Expand-ComputerLAPSInfo {
    <#
    .SYNOPSIS
        Enriches an AD computer object with LAPS password information

    .DESCRIPTION
        Refreshes and loads the LAPS attributes (ms-Mcs-AdmPwd and
        ms-Mcs-AdmPwdExpirationTime) on an AD computer object.

    .PARAMETER Computer
        The AD computer object to enrich.

    .PARAMETER Credential
        Optional PSCredential for AD authentication.

    .OUTPUTS
        None. The Computer object is modified in-place with LAPS properties.

    .EXAMPLE
        Expand-ComputerLAPSInfo -Computer $computer -Credential $cred

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory)]
        [object]$Computer,
        [pscredential]$Credential
    )
    Begin {
        function Test-ContainsArray {
            Param(
                [Parameter(Mandatory, Position = 0)]
                [object[]]$ReferenceArray,
                [Parameter(Mandatory, Position = 1)]
                [object[]]$ArrayContained
            )
            $oCompareResults = Compare-Object -ReferenceObject $ReferenceArray -DifferenceObject $ArrayContained -IncludeEqual -ExcludeDifferent
            return ($oCompareResults.Count -eq $ArrayContained.Count)
        }
        $aAdditionalProperties = @("ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime")
    }
    Process {
        $Computer.Remove("ms-Mcs-AdmPwd")
        $Computer.Remove("ms-Mcs-AdmPwdExpirationTime")
        if ($Credential) {
            Add-ADObjectProperties -ADObject $Computer -Properties $aAdditionalProperties -Credential $Credential
        } else {
            Add-ADObjectProperties -ADObject $Computer -Properties $aAdditionalProperties
        }
    }
}
