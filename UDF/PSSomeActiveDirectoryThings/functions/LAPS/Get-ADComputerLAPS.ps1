function Get-ADComputerLAPS {
    <#
    .SYNOPSIS
        Retrieves LAPS password data for an AD computer

    .DESCRIPTION
        Retrieves LAPS (Local Administrator Password Solution) information for a computer,
        supporting both legacy LAPS (ms-Mcs-AdmPwd) and Windows LAPS (msLAPS-Password,
        msLAPS-EncryptedPassword). Decrypts encrypted passwords using NCrypt APIs.
        Returns a hashtable with password, expiration, source, and optional decryptor info.

    .PARAMETER ADComputer
        The AD computer to retrieve LAPS data for: either an AD computer object
        (as returned by Get-ADComputer) or a string containing the computer name,
        which is resolved via Get-ADComputer -Identity.

    .PARAMETER Credential
        Optional PSCredential for AD authentication.

    .OUTPUTS
        System.Collections.Hashtable. Contains Computer, Source, Password, Account,
        Password Set Time, Password Expiration, and Authorized Decryptor. When a
        password history is present, "Password History" holds an array of past
        entries (each with ComputerName / Account / Password / Password Set Time /
        Authorized Decryptor). Includes a Refresh() method to reload the data.

    .EXAMPLE
        $computer = Get-ADComputer -Identity "WORKSTATION01"
        $laps = Get-ADComputerLAPS -ADComputer $computer

    .NOTES
        Author  : Loïc Ade
        Version : 1.1.0

        Dependencies: Invoke-AsCredential (PSSomeSystemThings)

        CHANGELOG:

        Version 1.1.0 - 2026-06-15 - Loïc Ade
            - Accept a computer name (string) for -ADComputer, resolved to an AD
              computer object via Get-ADComputer -Identity.
            - When -Credential is supplied, the DPAPI-NG decryption now runs
              impersonated as that account via Invoke-AsCredential. NCrypt decrypts
              under the current thread token, so the credential previously only
              authenticated the AD read and the password was never decrypted unless
              the console itself ran as an authorized decryptor.
            - Decrypt and expose the LAPS password history
              (msLAPS-EncryptedPasswordHistory) as "Password History". Payload
              parsing/cleaning factored into a shared helper used by both the
              current password and the history entries. Each history entry carries
              the PSTypeName "LAPS Historical Password".
            - Fixed FILETIME conversion: expiration and set-time used [datetime]<n>
              (ticks since year 0001 -> bogus years like 0426). Now use
              [datetime]::FromFileTime, which yields the correct local time.

        Version 1.0.0 - Loïc Ade
            - Initial release.
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADComputer,
        [Parameter(Position = 1)]
        [pscredential]$Credential
    )
    # Accept a computer name (string): resolve it to an AD computer object first.
    if ($ADComputer -is [string]) {
        $sComputerName = $ADComputer
        $ADComputer = if ($Credential) {
            Get-ADComputer -Identity $sComputerName -Credential $Credential
        } else {
            Get-ADComputer -Identity $sComputerName
        }
        if (-not $ADComputer) {
            throw "Computer '$sComputerName' not found in Active Directory."
        }
    }
    if (-not ([System.Management.Automation.PSTypeName]'LAPS_ncrypt').Type) {
        Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;

        public class LAPS_ncrypt
        {
            [Flags]
            public enum ProtectFlags
            {
                NCRYPT_SILENT_FLAG = 0x00000040,
            }

            public delegate int PFNCryptStreamOutputCallback(IntPtr pvCallbackCtxt, IntPtr pbData, int cbData, [MarshalAs(UnmanagedType.Bool)] bool fFinal);

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
            public struct NCRYPT_PROTECT_STREAM_INFO
            {
                public PFNCryptStreamOutputCallback pfnStreamOutput;
                public IntPtr pvCallbackCtxt;
            }

            [Flags]
            public enum UnprotectSecretFlags
            {
                NCRYPT_UNPROTECT_NO_DECRYPT = 0x00000001,
                NCRYPT_SILENT_FLAG = 0x00000040,
            }

            [DllImport("ncrypt.dll")]
            public static extern uint NCryptStreamOpenToUnprotect(ref NCRYPT_PROTECT_STREAM_INFO pStreamInfo, ProtectFlags dwFlags, IntPtr hWnd, out IntPtr phStream);

            [DllImport("ncrypt.dll")]
            public static extern uint NCryptStreamUpdate(IntPtr hStream, IntPtr pbData, int cbData, [MarshalAs(UnmanagedType.Bool)] bool fFinal);

            [DllImport("ncrypt.dll")]
            public static extern uint NCryptUnprotectSecret(out IntPtr phDescriptor, Int32 dwFlags, IntPtr pbProtectedBlob, uint cbProtectedBlob, IntPtr pMemPara, IntPtr hWnd, out IntPtr ppbData, out uint pcbData);

            [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
            public static extern uint NCryptGetProtectionDescriptorInfo(IntPtr hDescriptor, IntPtr pMemPara, int dwInfoType, out string ppvInfo);
        }
"@
    }

    # DPAPI-NG decryption of a Windows LAPS encrypted-password blob. Returns a
    # hashtable (Source / Password / AuthorizedDecryptor[SID]). It uses the global
    # [LAPS_ncrypt] type defined just above and closes over nothing but its byte[]
    # argument, so it can run under Invoke-AsCredential: NCrypt always decrypts under
    # the *current thread token*, so with a credential the decryption must run
    # impersonated as an authorized decryptor (the credential alone only authenticated
    # the AD read).
    $sbDecryptLAPS = {
        Param(
            [byte[]]$EncryptedPass
        )
        $oOut = @{}
        # The stream callback can fire several times; accumulate every chunk instead
        # of overwriting, then build the string once decryption completes.
        $aDecryptedBytes = New-Object System.Collections.Generic.List[byte]
        $delegateCallback = [LAPS_ncrypt+PFNCryptStreamOutputCallback]{
            Param(
                [IntPtr]$pvCallbackCtxt,
                [IntPtr]$pbData,
                [int]$cbData,
                [bool]$fFinal
            )
            if ($cbData -gt 0) {
                $data = New-Object byte[] $cbData
                [System.Runtime.InteropServices.Marshal]::Copy($pbData, $data, 0, $cbData)
                $aDecryptedBytes.AddRange($data)
            }
            return 0
        }
        $info = New-Object LAPS_ncrypt+NCRYPT_PROTECT_STREAM_INFO
        $info.pfnStreamOutput = $delegateCallback
        $info.pvCallbackCtxt = [IntPtr]::Zero

        $handle = [IntPtr]::Zero
        $handle2 = [IntPtr]::Zero
        $secData = [IntPtr]::Zero
        $secDataLen = 0

        $ret = [LAPS_ncrypt]::NCryptStreamOpenToUnprotect([ref]$info, [LAPS_ncrypt+ProtectFlags]::NCRYPT_SILENT_FLAG, [IntPtr]::Zero, [ref]$handle)
        if ($ret -eq 0) {
            $alloc = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($EncryptedPass.Length)
            [System.Runtime.InteropServices.Marshal]::Copy($EncryptedPass, 16, $alloc, $EncryptedPass.Length - 16)

            $ret = [LAPS_ncrypt]::NCryptUnprotectSecret([ref]$handle2, 0x41, $alloc, $EncryptedPass.Length - 16, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$secData, [ref]$secDataLen)
            if ($ret -eq 0) {
                $sid = ""
                $ret = [LAPS_ncrypt]::NCryptGetProtectionDescriptorInfo($handle2, [IntPtr]::Zero, 1, [ref]$sid)
                if ($ret -eq 0) {
                    $securityIdentifier = New-Object System.Security.Principal.SecurityIdentifier($sid.Substring(4, $sid.Length - 4))
                    try {
                        $oOut.AuthorizedDecryptor = $securityIdentifier.Translate([System.Security.Principal.NTAccount]).ToString()
                    } catch {
                        $oOut.AuthorizedDecryptorSID = $securityIdentifier.ToString()
                    }
                }
            }
            $ret = [LAPS_ncrypt]::NCryptStreamUpdate($handle, $alloc, $EncryptedPass.Length - 16, $true)

            if ($aDecryptedBytes.Count -gt 0) {
                $oOut.Source = "Windows LAPS Encrypted Password"
                # Decrypted secret is a UTF-16LE JSON string; strip all NUL chars
                # (the secret is null-terminated) before it is parsed as JSON.
                $oOut.Password = ([System.Text.Encoding]::Unicode.GetString($aDecryptedBytes.ToArray())).Replace([string][char]0, '')
            }
        }
        return $oOut
    }

    # Parse a decrypted Windows LAPS payload ({"n":account,"t":<hex FILETIME>,
    # "p":password}) into a clean hashtable (Account / Password / Password Set Time).
    # On a non-JSON payload, returns the raw value as Password.
    $sbParseLAPSPayload = {
        Param(
            [string]$Payload
        )
        $oParsed = @{}
        if ($Payload -like "{""n"":""*") {
            $sJson = $Payload
            $iEnd = $sJson.LastIndexOf('}')
            if ($iEnd -ge 0) { $sJson = $sJson.Substring(0, $iEnd + 1) }
            try {
                $oJson = $sJson | ConvertFrom-Json
                $oParsed.Account = $oJson.n
                $oParsed.Password = $oJson.p
                try { $oParsed."Password Set Time" = [datetime]::FromFileTime([int64]("0x$($oJson.t)")) } catch {}
            } catch {
                $oParsed.Password = $Payload
            }
        } else {
            $oParsed.Password = $Payload
        }
        return $oParsed
    }

    $attributeList = @(
        "msLAPS-PasswordExpirationTime",
        "msLAPS-Password",
        "msLAPS-EncryptedPassword",
        "msLAPS-EncryptedPasswordHistory",
        "msLAPS-EncryptedDSRMPassword",
        "msLAPS-EncryptedDSRMPasswordHistory",
        "ms-Mcs-AdmPwd",
        "ms-Mcs-AdmPwdExpirationTime"
    )
    $oADComputer = if ($Credential) { 
        Get-ADObject -Path $ADComputer.AdditionalProperties.Path -AdditionalProperties $attributeList -Credential $Credential
    } else {
        Get-ADObject -Path $ADComputer.AdditionalProperties.Path -AdditionalProperties $attributeList
    }
    $hResult = [ordered]@{
        Computer = $oADComputer
    }
    foreach ($sKey in $oADComputer.Keys) {
        switch ($sKey) {
            "ms-Mcs-AdmPwd" {
                if ($oADComputer.$sKey) {
                    $hResult.Source = "LAPS Legacy"
                    $hResult."Password" = $oADComputer.$sKey
                }
            }
            "ms-Mcs-AdmPwdExpirationTime" {
                if (($oADComputer."ms-Mcs-AdmPwd") -and ($oADComputer."ms-Mcs-AdmPwdExpirationTime")) {
                    $expiry = $oADComputer.$sKey
                    $hResult."Password Expiration" = [datetime]::FromFileTime([int64]$expiry)
                }
            }
            "msLAPS-PasswordExpirationTime" {
                if ($oADComputer.$sKey) {
                    $expiry = $oADComputer.$sKey
                    $hResult."Password Expiration" = [datetime]::FromFileTime([int64]$expiry)
                }
            }
            "msLAPS-Password" {
                $unencryptedPass = $oADComputer.$sKey
                $hResult.Password = $unencryptedPass
                $hResult.Source = "Windows LAPS Unencrypted password"
            }
            "msLAPS-EncryptedPassword" {
                # Decrypt impersonated as the supplied credential (DPAPI-NG decrypts
                # under the current thread token); otherwise decrypt as the current user.
                $oDecrypted = if ($Credential) {
                    Invoke-AsCredential -Credential $Credential -ScriptBlock $sbDecryptLAPS -ArgumentList (, $oADComputer.$sKey)
                } else {
                    & $sbDecryptLAPS $oADComputer.$sKey
                }
                if ($oDecrypted.Source) { $hResult.Source = $oDecrypted.Source }
                if ($oDecrypted.ContainsKey("Password")) { $hResult.Password = $oDecrypted.Password }
                if ($oDecrypted.AuthorizedDecryptor) { $hResult."Authorized Decryptor" = $oDecrypted.AuthorizedDecryptor }
                if ($oDecrypted.AuthorizedDecryptorSID) { $hResult."Authorized Decryptor SID" = $oDecrypted.AuthorizedDecryptorSID }
            }
            "msLAPS-EncryptedPasswordHistory" {
                # Multi-valued attribute: a single value comes back as one byte[]
                # (which must NOT be unrolled into individual bytes), several values
                # as a collection of byte[]. Decrypt each entry (impersonated) and
                # expose the parsed history, newest first as stored by AD.
                $oHistoryRaw = $oADComputer.$sKey
                $aHistoryEntries = if ($oHistoryRaw -is [byte[]]) {
                    , $oHistoryRaw
                } elseif ($oHistoryRaw) {
                    @($oHistoryRaw)
                } else {
                    @()
                }
                $aHistory = foreach ($oEntry in $aHistoryEntries) {
                    if ($oEntry -isnot [byte[]]) { continue }
                    $oDec = if ($Credential) {
                        Invoke-AsCredential -Credential $Credential -ScriptBlock $sbDecryptLAPS -ArgumentList (, $oEntry)
                    } else {
                        & $sbDecryptLAPS $oEntry
                    }
                    if (-not $oDec.ContainsKey("Password")) { continue }
                    $oParsed = & $sbParseLAPSPayload $oDec.Password
                    $oHistItem = [ordered]@{}
                    $oHistItem.ComputerName = $oADComputer.name
                    if ($oParsed.Account) { $oHistItem.Account = $oParsed.Account }
                    $oHistItem.Password = $oParsed.Password
                    if ($oParsed.ContainsKey("Password Set Time")) { $oHistItem."Password Set Time" = $oParsed."Password Set Time" }
                    if ($oDec.AuthorizedDecryptor) { $oHistItem."Authorized Decryptor" = $oDec.AuthorizedDecryptor }
                    elseif ($oDec.AuthorizedDecryptorSID) { $oHistItem."Authorized Decryptor SID" = $oDec.AuthorizedDecryptorSID }
                    # Give each entry a PSTypeName so callers can identify and
                    # format a historical password distinctly from a bare object.
                    $oHistObject = [pscustomobject]$oHistItem
                    $oHistObject.PSTypeNames.Insert(0, "LAPS Historical Password")
                    $oHistObject
                }
                if (@($aHistory).Count -gt 0) {
                    $hResult."Password History" = @($aHistory)
                }
            }
        }
    }
    if ($hResult.Password -like "{""n"":""*") {
        $oParsed = & $sbParseLAPSPayload $hResult.Password
        $hResult.Account = $oParsed.Account
        $hResult.Password = $oParsed.Password
        # Reorder so "Password Set Time" (from the payload) sits before the
        # expiration (from the msLAPS-PasswordExpirationTime attribute).
        $dExpiration = $hResult."Password Expiration"
        $hResult.Remove("Password Expiration")
        if ($oParsed.ContainsKey("Password Set Time")) { $hResult."Password Set Time" = $oParsed."Password Set Time" }
        if ($dExpiration) { $hResult."Password Expiration" = $dExpiration }
    }
    $hResult | Add-Member -MemberType ScriptMethod -Name "Refresh" -Value {
        $attributeList = @(
            "msLAPS-PasswordExpirationTime",
            "msLAPS-Password",
            "msLAPS-EncryptedPassword",
            "msLAPS-EncryptedPasswordHistory",
            "msLAPS-EncryptedDSRMPassword",
            "msLAPS-EncryptedDSRMPasswordHistory",
            "ms-Mcs-AdmPwd",
            "ms-Mcs-AdmPwdExpirationTime"
        )
        $oADObject = Get-ADObject -Path $this.Computer.AdditionalProperties.Path -AdditionalProperties $attributeList
        $oLAPS = Get-ADComputerLAPS $oADObject
        foreach ($sKey in $oLAPS.Keys) {
            $this.$sKey = $oLAPS.$sKey
        }
    }
    $hResult.PSTypeNames.Insert(0, "ADComputerLAPS")
    return $hResult
}
