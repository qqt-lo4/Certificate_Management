function Convert-ADObjectValue {
    <#
    .SYNOPSIS
        Converts raw AD property values to typed wrapper objects

    .DESCRIPTION
        Takes an AD property name and its raw value(s), and returns a typed wrapper
        object based on the property type. Supports AD dates (lastLogon, pwdLastSet, etc.),
        object GUIDs, SIDs, object classes, certificates, and thumbnail photos.
        Each wrapper provides a meaningful ToString() and GetValue() method.

    .PARAMETER Property
        The AD property name to determine the conversion type.

    .PARAMETER Value
        The raw value(s) of the AD property to convert.

    .OUTPUTS
        [object]. A typed wrapper object (ADDate, ADObjectGUID, ADObjectSID, ADObjectClass,
        ADObjectCert, ADObjectPicture) or the original value if no conversion applies.

    .EXAMPLE
        Convert-ADObjectValue -Property "pwdlastset" -Value $user.pwdlastset

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Property,
        [Parameter(Mandatory, Position = 1)]
        [object[]]$Value
    )
    Begin {
        class ADDate {
            hidden $_value
            ADDate($value) {
                $this._value = $value
            }
            [string] ToString() {
                if ($this.IsNever()) {
                    return "Never"
                } else {
                    return ([datetime]::FromFileTimeUtc($this._value)).ToLocalTime().ToString()
                }
            }
            [object] GetValue() {
                return $this._value
            }
            [datetime] GetDate() {
                return ([datetime]::FromFileTimeUtc($this._value).ToLocalTime())
            }
            [bool] IsNever() {
                return $this._value -in @(0, ($this._value.GetType())::MaxValue)
            }
        }
        
        class ADObjectClass {
            hidden $value
            ADObjectClass([object[]]$value) {
                $this.value = $value
            }
            [object] GetValue() {
                return $this.value
            }
            [string] ToString() {
                return $this.value[$this.value.Count - 1]
            }
        }

        class ADObjectGUID {
            hidden $value
            ADObjectGUID([object[]]$value) {
                $this.value = $value
            }
            [object] GetValue() {
                return $this.value
            }
            [string] ToString() {
                $aHexa = $this.value | ForEach-Object ToString X2
                return ($aHexa[3..0] -join '') + "-" + ($aHexa[5..4] -join '') + "-" + `
                       ($aHexa[7..6] -join '') + "-" + ($aHexa[9..8] -join '') + "-" + `
                       ($aHexa[15..10] -join '')
            }
        }

        class ADObjectCert {
            hidden $value
            ADObjectCert([object]$value) {
                $this.value = $value
            }
            [object] GetValue() {
                return $this.value
            }
            [System.Security.Cryptography.X509Certificates.X509Certificate2] GetCert() {
                if ($Global:PSVersionTable.PSVersion -lt [version]"6.0") {
                    $oResult = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 
                    $oResult.Import([byte[]]$this.value)
                } else {
                    $oResult = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,[byte[]]$this.value)
                }
                return $oResult
            }
            [string] ToString() {
                $oCert = $this.GetCert()
                return ($oCert.Subject -replace ", ", ",") + " (" + $oCert.Thumbprint + ")"
            }
        }

        class ADObjectPicture {
            hidden $value
            ADObjectPicture([object]$value) {
                $this.value = $value
            }
            [object] GetValue() {
                return $this.value
            }
            [string] ToString() {
                return "Picture can't be displayed on terminal"
            }
        }

        class ADArrayOfByteArray {
            hidden $value
            ADObjectPicture([object]$value) {
                $this.value = $value
            }
            [object] GetValue() {
                return $this.value
            }
            [string] ToString() {
                if ($this.value.GetType() -eq "Object[]") {
                    return ($this.value | ForEach-Object { $_ -join ", " }) | ForEach-Object { "{$_}" }
                } else {
                    return "{" + ($this.value -join ", ") + "}"
                }
            }
        }

        class ADObjectSID {
            hidden $value
            ADObjectSID([object[]]$value) {
                $this.value = $value
            }
            [object] GetValue() {
                return $this.value
            }
            [string] ToString() {
                $objectSid = [byte[]]$this.value
                $sid = New-Object System.Security.Principal.SecurityIdentifier($objectSid,0) 
                return ($sid.value).ToString()
            }
        }
        
        function Get-ObjectType {
            Param(
                [Parameter(Mandatory, Position = 0)]
                [string]$PropertyName
            )
            switch ($PropertyName) {
                {$PSItem -in @("badpasswordtime", "lastlogontimestamp", "accountexpires", "lastlogon", "pwdlastset", "lockouttime", "msds-userpasswordexpirytimecomputed", "ms-Mcs-AdmPwdExpirationTime")} {
                    "ADDate"
                }
                "objectguid" { "ObjectGUID" }
                "msexcharchiveguid" { "ObjectGUID" }
                "msexchmailboxguid" { "ObjectGUID" }
                "ms-ds-consistencyguid" { "ObjectGUID" }
                "objectsid" { "ObjectSID" }
                "objectclass" { "ADObjectClass" }
                "usercertificate" { "ADObjectCert[]" }
                "thumbnailphoto" { "ADObjectPicture" }
                #"msmqdigests" { "Object[Byte[]]" }
                default { "" }
            }
        }
        
    }
    Process {
        $sType = Get-ObjectType -PropertyName $Property
        $oValue = if ($Value.Count -gt 1) { $Value } else { $Value[0] }
        switch ($sType) {
            "ADDate" { return New-Object ADDate($oValue) }
            "ADObjectClass" { return New-Object ADObjectClass(@(,$oValue)) }
            "ObjectGUID" { return New-Object ADObjectGUID(@(,$oValue))}
            "ObjectSID" { return New-Object ADObjectSID(@(,$oValue))}
            "ADObjectCert[]" {
                $bOneCertificate = ($oValue[0].GetType().Name -eq "Byte")
                if ($bOneCertificate) { 
                    return [ADObjectCert]$oValue 
                } else {
                    return [ADObjectCert[]]$oValue 
                }
            }
            "ADObjectPicture" { return [ADObjectPicture]$oValue }
            "" { return $oValue }
        }    
    }
}
