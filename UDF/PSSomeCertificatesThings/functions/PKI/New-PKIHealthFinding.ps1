function New-PKIHealthFinding {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [ValidateSet(
            'Healthy',
            'Warning',
            'Critical',
            'Unknown',
            'NotApplicable'
        )]
        [string]$Status,

        [Parameter(Mandatory)]
        [string]$Authority,

        [Parameter(Mandatory)]
        [string]$Check,

        [Parameter(Mandatory)]
        [string]$Details,

        [AllowNull()]
        [string]$URL,

        [AllowNull()]
        [object]$ThisUpdate,

        [AllowNull()]
        [object]$NextUpdate,

        [AllowNull()]
        [object]$NextPublish,

        [AllowNull()]
        [object]$DaysRemaining,

        [AllowNull()]
        [string]$SignatureStatus
    )

    [PSCustomObject]@{
        Status          = $Status
        Authority       = $Authority
        Check           = $Check
        Details         = $Details
        URL             = $URL
        ThisUpdate      = $ThisUpdate
        NextUpdate      = $NextUpdate
        NextPublish     = $NextPublish
        DaysRemaining   = $DaysRemaining
        SignatureStatus = $SignatureStatus
    }
}