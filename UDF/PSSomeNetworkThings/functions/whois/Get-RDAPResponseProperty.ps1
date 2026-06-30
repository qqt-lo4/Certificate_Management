function Get-CleanRdapContact {
    <#
    .SYNOPSIS
        Builds a single-line, human-readable string for an RDAP contact role.

    .DESCRIPTION
        Extracts the entity matching the requested role from an RDAP response,
        flattens its contact card (name, email, phone, address) and joins the
        populated fields into a single comma-separated string.

    .PARAMETER RdapResponse
        The RDAP response object (as returned by Invoke-RDAPQuery).

    .PARAMETER Contact
        The role to extract (e.g. "registrar", "registrant", "technical",
        "administrative", "abuse").

    .OUTPUTS
        [string]. The flattened contact information.

    .EXAMPLE
        Get-CleanRdapContact -RdapResponse $r -Contact "registrar"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [object]$RdapResponse,
        [Parameter(Mandatory, Position = 1)]
        [string]$Contact
    )
    $oContact = ($RdapResponse.Entities | Where-Object { $Contact -in $_.Roles }).Contact
    $hClean = $oContact | ConvertTo-Hashtable | Clear-EmptyHashtableValues
    if ($hClean.Email) {
        $hClean.Email = $hClean.Email -join ", "
    }
    if ($hClean.Phone) {
        $aPhones = @()
        foreach ($hPhone in $hClean.Phone) {
            $aPhones += ($hPhone.Number + " ($($hPhone.Type))")
        }
        $hClean.Phone = $aPhones -join ", "
    }
    $sResult = $hClean.Name
    if ($hClean.Email) {
        $sResult += ", " + $hClean.Email
    }
    if ($hClean.Phone) {
        $sResult += ", " + $hClean.Phone
    }
    if ($hClean.Address) {
        $sResult += ", " + $hClean.Address
    }
    return $sResult
}

function Get-RDAPResponseEventDate {
    <#
    .SYNOPSIS
        Returns the date of a named event from an RDAP response.

    .DESCRIPTION
        Looks up an event by action in the RDAP response Events collection and
        returns its EventDate, or $null when the event is absent.

    .PARAMETER RdapResponse
        The RDAP response object (as returned by Invoke-RDAPQuery).

    .PARAMETER EventName
        The event action to look up (e.g. "registration", "last changed").

    .OUTPUTS
        [DateTime] or $null.

    .EXAMPLE
        Get-RDAPResponseEventDate -RdapResponse $r -EventName "registration"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [object]$RdapResponse,
        [Parameter(Mandatory, Position = 1)]
        [string]$EventName
    )
    $oEvent = $RdapResponse.Events | Where-Object { $_.EventAction -eq "expiration" }
    if ($oEvent) {
        return $oEvent.EventDate
    } else {
        return $null
    }
}

function Test-RDAPResponseEvent {
    <#
    .SYNOPSIS
        Tests whether an RDAP response carries a given event.

    .DESCRIPTION
        Returns $true when the RDAP response contains an event matching the
        requested name (delegates the lookup to Get-RDAPResponseEventDate).

    .PARAMETER RdapResponse
        The RDAP response object (as returned by Invoke-RDAPQuery).

    .PARAMETER EventName
        The event action to test for.

    .OUTPUTS
        [bool].

    .EXAMPLE
        Test-RDAPResponseEvent -RdapResponse $r -EventName "registration"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline)]
        [object]$RdapResponse,
        [Parameter(Mandatory, Position = 1)]
        [string]$EventName
    )
    $dEventDate = Get-RDAPResponseEventDate @PSBoundParameters
    return $null -ne $dEventDate
}

function Test-RdapContact {
    <#
    .SYNOPSIS
        Tests whether an RDAP response carries a given contact role.

    .DESCRIPTION
        Returns $true when at least one entity in the RDAP response holds the
        requested role.

    .PARAMETER RdapResponse
        The RDAP response object (as returned by Invoke-RDAPQuery).

    .PARAMETER Contact
        The role to test for (e.g. "registrar", "abuse").

    .OUTPUTS
        [bool].

    .EXAMPLE
        Test-RdapContact -RdapResponse $r -Contact "registrar"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$RdapResponse,
        [Parameter(Mandatory, Position = 1)]
        [string]$Contact
    )
    return (($RdapResponse.Entities | Where-Object { $Contact -in $_.Roles }) -ne $null)
}
