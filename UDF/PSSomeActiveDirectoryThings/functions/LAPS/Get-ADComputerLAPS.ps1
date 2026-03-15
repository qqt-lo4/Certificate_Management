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
        The AD computer object to retrieve LAPS data for.

    .PARAMETER Credential
        Optional PSCredential for AD authentication.

    .OUTPUTS
        System.Collections.Hashtable. Contains Computer, Source, Password, Account,
        Password Set Time, Password Expiration, and Authorized Decryptor. Includes
        a Refresh() method to reload the data.

    .EXAMPLE
        $computer = Get-ADComputer -Identity "WORKSTATION01"
        $laps = Get-ADComputerLAPS -ADComputer $computer

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, Position = 0)]
        [object]$ADComputer,
        [Parameter(Position = 1)]
        [pscredential]$Credential
    )
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

    $delegateCallback = [LAPS_ncrypt+PFNCryptStreamOutputCallback]{
        Param(
            [IntPtr]$pvCallbackCtxt,
            [IntPtr]$pbData,
            [int]$cbData,
            [bool]$fFinal
        )
        $data = New-Object byte[] $cbData
        [System.Runtime.InteropServices.Marshal]::Copy($pbData, $data, 0, $cbData)
        $str = [System.Text.Encoding]::Unicode.GetString($data)
        $hResult.Source = "Windows LAPS Encrypted Password"
        $hResult.Password = $str
        return 0
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
                    $hResult."Password Expiration" = [datetime]$expiry
                }
            }
            "msLAPS-PasswordExpirationTime" {
                if ($oADComputer.$sKey) {
                    $expiry = $oADComputer.$sKey
                    $hResult."Password Expiration" = [datetime]$expiry
                }
            }
            "msLAPS-Password" {
                $unencryptedPass = $oADComputer.$sKey
                $hResult.Password = $unencryptedPass
                $hResult.Source = "Windows LAPS Unencrypted password"
            }
            "msLAPS-EncryptedPassword" {
                $encryptedPass = $oADComputer.$sKey
    
                $info = New-Object LAPS_ncrypt+NCRYPT_PROTECT_STREAM_INFO
                $info.pfnStreamOutput = $delegateCallback
                $info.pvCallbackCtxt = [IntPtr]::Zero
        
                $handle = [IntPtr]::Zero
                $handle2 = [IntPtr]::Zero
                $secData = [IntPtr]::Zero
                $secDataLen = 0
                $ntaccount = $null
        
                $ret = [LAPS_ncrypt]::NCryptStreamOpenToUnprotect([ref]$info, [LAPS_ncrypt+ProtectFlags]::NCRYPT_SILENT_FLAG, [IntPtr]::Zero, [ref]$handle)
                if ($ret -eq 0) {
                    $alloc = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($encryptedPass.Length)
                    [System.Runtime.InteropServices.Marshal]::Copy($encryptedPass, 16, $alloc, $encryptedPass.Length - 16)
        
                    $ret = [LAPS_ncrypt]::NCryptUnprotectSecret([ref]$handle2, 0x41, $alloc, $encryptedPass.Length - 16, [IntPtr]::Zero, [IntPtr]::Zero, [ref]$secData, [ref]$secDataLen)
                    if ($ret -eq 0) {
                        $sid = ""
        
                        $ret = [LAPS_ncrypt]::NCryptGetProtectionDescriptorInfo($handle2, [IntPtr]::Zero, 1, [ref]$sid)
                        if ($ret -eq 0) {
                            $securityIdentifier = New-Object System.Security.Principal.SecurityIdentifier($sid.Substring(4, $sid.Length - 4))
                            try {
                                $ntaccount = $securityIdentifier.Translate([System.Security.Principal.NTAccount])
                                $hResult."Authorized Decryptor" = $ntaccount.ToString()
                            } catch {
                                $hResult."Authorized Decryptor SID" = $securityIdentifier.ToString()
                            }
                        }
                    }
        
                    $ret = [LAPS_ncrypt]::NCryptStreamUpdate($handle, $alloc, $encryptedPass.Length - 16, $true)
                }    
            }
        }
    }
    if ($hResult.Password -like "{""n"":""*") {
        $oJson = $hResult.Password | ConvertFrom-Json
        $hResult.Remove("Password")
        $hResult.Account = $oJson.n
        $hResult.Password = $oJson.p
        $dExpiration = $hResult."Password Expiration" 
        $hResult.Remove("Password Expiration")
        $hResult."Password Set Time" = ([datetime][int64]"0x$($oJson.t)").ToLocalTime()
        $hResult."Password Expiration" = $dExpiration.ToLocalTime()
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
