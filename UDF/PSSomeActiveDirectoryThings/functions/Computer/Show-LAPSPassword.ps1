function Show-LAPSPassword {
    <#
    .SYNOPSIS
        Displays the LAPS password for an AD computer object

    .DESCRIPTION
        Retrieves and displays the LAPS (Local Administrator Password Solution) password
        and expiration date for a computer object, with colored DN formatting.

    .PARAMETER Computer
        The AD computer object to display LAPS info for.

    .PARAMETER Credential
        Optional PSCredential for authenticating to AD.

    .OUTPUTS
        None. Outputs formatted LAPS information to the console.

    .EXAMPLE
        $computer = Get-ADComputer -Identity "WORKSTATION01"
        Show-LAPSPassword -Computer $computer

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$Computer,
        [pscredential]$Credential
    )
    Begin {
        if ($Credential) {
            Expand-ComputerLAPSInfo -Computer $Computer -Credential $Credential | Out-Null
        } else {
            Expand-ComputerLAPSInfo -Computer $Computer | Out-Null
        }
        $aResultProperties = @(@{N="Path"; E={$_.adspath}},
                               @{N="Name"; E={$_.name}}, 
                               @{N="Expiration Date"; E={$_."ms-Mcs-AdmPwdExpirationTime"}}, 
                               @{N="Password"; E={$_."ms-Mcs-AdmPwd"}})
        $sDNRegex = "((?<attrib>(E|CN|OU|DC)=)(?<val>[^,:=/]+)(?<comma>,))+((?<attrib>(E|CN|OU|DC)=)(?<val>[^,:=/]+))"
        $sPathRegex = "(?<protocol>[a-zA-Z]+://)?(?<server>[a-zA-Z_.0-6:-]+/)?" + $sDNRegex
        $aPropertiesValuesToColor = @(
            @{Property = "Path" ; Pattern = $sPathRegex ; Color = $HighlightColor ; ColorGroups = @("val") ; AllMatches = $true}
        )
        $Computer | Select-Object -Property $aResultProperties `
                  | Format-ListCustom -PropertiesColor Green -PropertiesValuesToColor $aPropertiesValuesToColor
    }
}
