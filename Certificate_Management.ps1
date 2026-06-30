Param(
    [string]$InputDir,
    [string]$WorkingDir
)

$iModulesCount = 8
$i = 0

#region Include
# Remove the Mark-of-the-Web from the bundled native tools before using them. When this folder
# is downloaded from another machine and extracted from a ZIP, Windows tags every file with a
# Zone.Identifier (MOTW); the bundled OpenSSL and 7-Zip executables and their DLLs then refuse
# to run / load. All bundled binaries live under tools, so we unblock its *.exe and *.dll.
Get-ChildItem -Path (Join-Path $PSScriptRoot "tools") -Recurse -Include '*.exe', '*.dll' -File -ErrorAction SilentlyContinue |
    Unblock-File -ErrorAction SilentlyContinue

Write-Progress -Activity "Loading script modules" -Status "PSSomeActiveDirectoryThings" -PercentComplete (($($i++; $i) / $iModulesCount) * 100)
Import-Module $PSScriptRoot\UDF\PSSomeActiveDirectoryThings -Force
Write-Progress -Activity "Loading script modules" -Status "PSSomeAuthThings" -PercentComplete (($($i++; $i) / $iModulesCount) * 100)
Import-Module $PSScriptRoot\UDF\PSSomeAuthThings -Force
Write-Progress -Activity "Loading script modules" -Status "PSSomeCertificatesThings" -PercentComplete (($($i++; $i) / $iModulesCount) * 100)
Import-Module $PSScriptRoot\UDF\PSSomeCertificatesThings -Force -WarningAction SilentlyContinue
Write-Progress -Activity "Loading script modules" -Status "PSSomeCLIThings" -PercentComplete (($($i++; $i) / $iModulesCount) * 100)
Import-Module $PSScriptRoot\UDF\PSSomeCLIThings -Force
Write-Progress -Activity "Loading script modules" -Status "PSSomeCoreThings" -PercentComplete (($($i++; $i) / $iModulesCount) * 100)
Import-Module $PSScriptRoot\UDF\PSSomeCoreThings -Force
Write-Progress -Activity "Loading script modules" -Status "PSSomeDataThings" -PercentComplete (($($i++; $i) / $iModulesCount) * 100)
Import-Module $PSScriptRoot\UDF\PSSomeDataThings -Force
Write-Progress -Activity "Loading script modules" -Status "PSSomeFileThings" -PercentComplete (($($i++; $i) / $iModulesCount) * 100)
Import-Module $PSScriptRoot\UDF\PSSomeFileThings -Force
Write-Progress -Activity "Loading script modules" -Status "PSSomeNetworkThings" -PercentComplete (($($i++; $i) / $iModulesCount) * 100)
Import-Module $PSScriptRoot\UDF\PSSomeNetworkThings -Force
Write-Progress -Activity "Loading script modules" -Status "Loading end" -PercentComplete 100 -Completed
#endregion Include

#region script info
#scriptVersion=2.5
#endregion script info

#region Release notes
<#1.0: First release

1.1: 
Added:
- now there is a way to repeat the certificate object form (so you can validate entered values are correct)
- a way to not specify the template name
Fixed:
- the State value should be okay now (it was impossible to fill this value)
- corrected the form to allow CN with stars, and french accented letters for other values

1.1.1:
Changed:
- Changed Get-Credential to Read-Credential because of a bug

2.0:
- Added CN verification in SAN
- Added an all in one option (all old menu items are moved in "Advanced" menu)
- PKI work folder is no more hardcoded

2.1:
- Changed DN form for better UI
- Using Invoke-YesNoCLIDialog instead of Read-YesNoAnswer for better UI
- Changed main menu for better UI

2.2:
- Changed UI to allow back almost everywhere

2.3: 
- First public version
- Added import certificate from to create a new one
- Improved pfx creation :
    files are requested if not present,
    and missing CA certs are imported from user and computer stores

2.4:
- Added "Import from existing certificate" under Advanced > New Certificate Request to generate a CSR only from an existing certificate

2.5 (2026-06-21):
- Added "Sign a provided CSR": enter the path of a CSR, display it for review
  (the signer may decline), choose the CA and the template (the requester rarely
  provides one), and write the signed certificate + chain to a working folder named
  after the subject CN. No PFX is produced (the private key stays with the requester).
- Added "Export / Convert certificate": converts a PFX to other output formats
  (PFX with/without password, PEM combined, PEM separate, DER) through a single
  options form. The source PFX can be picked from a working-folder certificate or
  from any external file path (which is copied into a new working subfolder named
  "<pfx>_<date>" that becomes the working folder for the rest of the flow). When the
  output would contain an unencrypted private key, a password is enforced and the
  result is stored in a password-protected ZIP (AES-256 for security, or ZipCrypto
  for Windows Explorer compatibility).

#>
#endregion Release notes

$sCertInfoFileName = "CertInfo.json"

function Get-CertInfo {
    Param(
        [Parameter(Mandatory)]
        [string]$CertFolder
    )
    $sPath = $CertFolder + "\" + $sCertInfoFileName
    if ((Test-Path $sPath -PathType Leaf) -and ((Get-Item $sPath).Length -gt 0)) {
        return Get-Content $sPath | ConvertFrom-Json
    }
    return $null
}

function Save-CertInfo {
    Param(
        [Parameter(Mandatory)]
        [string]$CertFolder,
        [Parameter(Mandatory)]
        [object]$CertInfo
    )
    $CertInfo | ConvertTo-Json -Depth 10 | Out-File ($CertFolder + "\" + $sCertInfoFileName)
}

function Get-OpenSSLLocation {
    return (Get-ScriptDir -ToolsDir -ToolName "OpenSSL-Win64") + "\openssl.exe"
}

function Read-CertificateObject {
    $Menu = New-Menu -Text "Please specify the certificate object" -Content @(
        New-MenuItem -Text "&Full Object DN" -Content {
            $oResult = Read-CLIDialogDN -Header "Please enter certificate object as DN format" -AllowBack 
            if ($null -ne $oResult -and $oResult.PSTypeNames -and $oResult.PSTypeNames[0] -eq "DialogResult.Action.Back") {
                return $null
            }
            return [ordered]@{Subject = $oResult}
        }
        New-MenuItem -Text "&Ask for items (recommended)" -Content {
            $sFreeStringRegex = "^$|^[0-9a-zA-Zéèàùêëîï _.-]+$"
            $hCertProps = [ordered]@{
                CommonName = @{regex = "^[0-9a-zA-Z ._*-]+$"}
                Organisation = @{regex = $sFreeStringRegex}
                OrganisationalUnit = @{regex = $sFreeStringRegex}
                Locality = @{regex = $sFreeStringRegex}
                State = @{regex = $sFreeStringRegex}
                CountryCode = @{regex = "^$|^..$"}
            }
            $oResult = Read-CLIDialogHashtable -Properties $hCertProps -AllowBack
            if ($null -ne $oResult -and $oResult.PSTypeNames -and $oResult.PSTypeNames[0] -eq "DialogResult.Action.Back") {
                return $null
            }
            return $oResult
        } -Recommended
    ) -SeparatorColor Blue -OtherMenuItems @(
        New-MenuAction -Back -Text "&Back"
        New-MenuAction -Exit -Text "&Exit"
    )
    return Invoke-Menu -Menu $Menu
}

function Read-CA {
    Param(
        [string]$CANameFilter,
        [string]$DefaultCAName
    )
    $sCANameFilter = if ($CANameFilter) {
        $CANameFilter
    } else {
        if ($ScriptConfig.CAFilter -and ($ScriptConfig.CAFilter -ne "")) {
            $ScriptConfig.CAFilter
        }
    }
    $aCA = if ($sCANameFilter) { Get-CA -Filter $sCANameFilter } else { Get-CA }
    $aMoreButtons = @(
        New-CLIDialogButton -Other -Text "Do not include a template name" -Object { return "" }
        New-CLIDialogButton -Text "&Back" -Back
    )
    # was Select-CLIObjectInArray
    $hSelectParams = @{
        Objects = $aCA
        SelectHeaderMessage = "Please select the CA"
        SelectedColumns = @{ l = "CA Name" ; e = { $_.Name } }
        OtherMenuItems = $aMoreButtons
        DontShowPageNumberWhenOnlyOnePage = $true
        FooterMessage = ""
        SeparatorColor = [System.ConsoleColor]::Blue
        Space = $true
        HeaderTextInSeparator = $true
    }
    if ($DefaultCAName) {
        $hSelectParams.SelectedObjects = @($DefaultCAName)
        $hSelectParams.SelectedObjectsUniqueProperty = "Name"
    }
    $oResult = Select-CLIDialogObjectInArray @hSelectParams
    if ($oResult.PSTypeNames -and $oResult.PSTypeNames[0] -eq "DialogResult.Action.Back") {
        return New-DialogResultAction -Action "Back"
    }
    return $oResult.Value
}

function Read-TemplateName {
    Param(
        [object]$CA = (Read-CA),
        [string]$TemplateFilter,
        [string]$DefaultTemplateName
    )
    $aCT = if ($CA) { 
        $sCAName = if ($CA.PSObject.TypeNames[0] -eq "ADcertificationAuthority") {
            $CA.Name
        } else {
            $CA
        }
        Get-PublishedCertificateTemplates -CA $sCAName
    } else {
        Get-PublishedCertificateTemplates 
    }
    if ($TemplateFilter) {
        $aCT = $aCT | Where-Object { $_.name -match $TemplateFilter }
    }
    $aOtherButtons = @(
        New-CLIDialogButton -Text "Type another template name (for an external PKI)" -Other -Object {
            return Read-Host -Prompt "Type another template name"
        }
        New-CLIDialogButton -Text "&Back" -Back
    )
    $hSelectParams = @{
        Objects = $aCT
        SelectedColumns = @{ l = "Template Name"; e = { $_.displayname} }
        SelectHeaderMessage = "Please select the template name"
        HeaderColor = [System.ConsoleColor]::Blue
        OtherMenuItems = $aOtherButtons
        FooterMessage = ""
        SeparatorColor = [System.ConsoleColor]::Blue
        HeaderTextInSeparator = $true
        Space = $true
        DontShowPageNumberWhenOnlyOnePage = $true
    }
    if ($DefaultTemplateName) {
        $hSelectParams.SelectedObjects = @($DefaultTemplateName)
        $hSelectParams.SelectedObjectsUniqueProperty = "name"
    }
    $oItem = Select-CLIDialogObjectInArray @hSelectParams
    if ($oItem.PSTypeNames -and $oItem.PSTypeNames[0] -eq "DialogResult.Action.Back") {
        return New-DialogResultAction -Action "Back"
    }
    $hResult = @{}
    if ($oItem.Type -eq "Value") {
        $hResult.Add("CertificateTemplate", $oItem.Value.name)
    } else {
        if ($oItem.Value -ne "") {
            $hResult.Add("CertificateTemplate", $oItem.Value)
        }
    }
    return $hResult
}

function Read-KeyPassword {
    Param(
        [securestring]$DefaultValue,
        [switch]$AllowBack
    )
    $oResult = Read-CLIDialogNewPassword `
        -Header "Private key password" `
        -ErrorNotMatching "Key passwords are not the same, please try again" `
        -AllowEmpty `
        -EmptyConfirmMessage "The entered password is empty. Do you confirm the private key will not be protected?" `
        -EmptyConfirmYes "Yes, keep the key without password" `
        -EmptyConfirmNo "No, enter a password" `
        -AllowBack:$AllowBack `
        -DefaultValue $DefaultValue
    if ($null -ne $oResult -and $oResult.PSTypeNames -and $oResult.PSTypeNames[0] -eq "DialogResult.Action.Back") {
        return $oResult
    }
    if ($null -eq $oResult -or $oResult.Length -eq 0) {
        return @{}
    } else {
        return @{KeyPassword = $oResult}
    }
}

function Read-FileNames {
    Param(
        [string]$DefaultFriendlyName,
        [switch]$AllowBack
    )
    $oFriendlyName = Read-CLIDialogFilePath `
        -Header "Please enter a friendly name. It will be used to generate certificate files and used in the pfx." `
        -PropertyName "Friendly name" -AllowNonExisting -AllowBack:$AllowBack `
        -DefaultValue $DefaultFriendlyName -ErrorMessage "Friendly name cannot be empty"
    if ($null -ne $oFriendlyName -and $oFriendlyName.PSTypeNames -and $oFriendlyName.PSTypeNames[0] -eq "DialogResult.Action.Back") {
        return $oFriendlyName
    }
    $sFriendlyName = $oFriendlyName
    # The friendly name can legitimately contain characters that are illegal in Windows paths
    # (e.g. a wildcard "*.example.com"). Keep $sFriendlyName as-is for the PFX friendly name, but
    # derive a file-system-safe name for the working folder and the generated file names.
    $sSafeName = ConvertTo-SafeFileName -Name $sFriendlyName
    $sWorkingDir = Get-ScriptDir -WorkingDir
    $sRealFolderName = $sSafeName
    $sFinalFolderName = $sWorkingDir + "\" + $sSafeName
    if (Test-Path ($sFinalFolderName)) {
        $sRealFolderName = $sSafeName + "_" + (Get-Date -Format "yyyyMMdd-HHmmss")
        $sFinalFolderName = $sWorkingDir + "\" + $sRealFolderName
    }
    New-Item -Path $sFinalFolderName -ItemType Directory | Out-Null
    $sKeyFileName = $sFinalFolderName + "\" + $sSafeName + ".key"
    $sCSRFileName = $sFinalFolderName + "\" + $sSafeName + ".req"
    $sConfigFileName = $sFinalFolderName + "\" + $sSafeName + ".inf"
    $hResult = @{
        SettingsInfPath = $sConfigFileName
        KeyOutPath = $sKeyFileName
        CSROutPath = $sCSRFileName
        FriendlyName = $sFriendlyName
        SafeName = $sSafeName
        FolderName = $sRealFolderName
    }
    return $hResult
}

function Read-SAN {
    Param(
        [string]$CommonName,
        [switch]$AskForValidation,
        [switch]$AllowBack,
        [hashtable]$PreviousValues
    )
    Begin {
        function Read-SANIPandDNS {
            Param([string]$DefaultValue, [switch]$AllowBack)
            $hProperties = [ordered]@{
                IP = @{Regex = Get-IPRegex -FullLine; IgnoreOtherRegex = $true}
                DNS = @{Regex = Get-DNSRegex -FullLine -AllowWildcard}
            }
            $hParams = @{
                Header = "Subject Alternative Names"
                TextBoxHeader = "DNS / IP"
                HintMessage = "Enter DNS names and IP addresses, one per line.`nUse Tab or Down arrow on the last line to navigate to the buttons."
                VisibleLines = 4
                GroupByProperties = $hProperties
                AllowBack = $AllowBack
            }
            if ($DefaultValue) {
                $hParams.DefaultValue = $DefaultValue
            }
            return Read-CLIDialogArray @hParams
        }
    }
    Process {
        $bResultOK = $false
        $hResult = @{}

        # If previous values exist, start at the validation step
        $bSkipInput = $false
        if ($PreviousValues -and ($PreviousValues.SANdns -or $PreviousValues.SANipaddress)) {
            $hResult = $PreviousValues.Clone()
            $bSkipInput = $true
        }

        while (-not $bResultOK) {
            if (-not $bSkipInput) {
                $sDefaultValue = if ($hResult.SANdns -or $hResult.SANipaddress) {
                    ((@($hResult.SANdns) + @($hResult.SANipaddress)) | Where-Object { $_ }) -join "`n"
                } else { $null }
                $hSANs = Read-SANIPandDNS -DefaultValue $sDefaultValue -AllowBack:$AllowBack
                # Handle Back
                if ($hSANs.PSTypeNames -and $hSANs.PSTypeNames[0] -like "DialogResult.Action.*") {
                    return $hSANs
                }
                if (-not ($CommonName -in $hSANs.DNS)) {
                    $sAnswer = Invoke-YesNoCLIDialog -Message "The Common Name of the certificate ($CommonName) should be in subject alternative names" `
                                                     -Vertical -YN -YesButtonText "Include in DNS SAN" `
                                                     -NoButtonText "Do not include in SAN"
                    if ($sAnswer -eq "Yes") {
                        $hSANs.DNS += $CommonName
                    }
                }
                $hResult = @{}
                if ($hSANs.DNS.Count -gt 0) {
                    $hResult.SANdns = $hSANs.DNS
                }
                if ($hSANs.IP.Count -gt 0) {
                    $hResult.SANipaddress = $hSANs.IP
                }
            }
            $bSkipInput = $false

            if ($AskForValidation.IsPresent) {
                Write-Host "Entered subject alternative names:"
                Write-Host "DNS = $($hResult.SANdns -join ",")"
                Write-Host "IP = $($hResult.SANipaddress -join ",")"
                $hYNCParams = @{
                    Message = "Do you accept these subject alternative names?"
                    Vertical = $true
                    YesButtonText = "&Yes"
                    NoButtonText = "&No, change subject alternative names"
                    CancelButtonText = "&Back"
                }
                if ($AllowBack) {
                    $hYNCParams.YNC = $true
                } else {
                    $hYNCParams.YN = $true
                }
                $oAnswer = Invoke-YesNoCLIDialog @hYNCParams
                switch ($oAnswer) {
                    "Yes" {
                        $bResultOK = $true
                    }
                    "Cancel" {
                        return New-DialogResultAction -Action "Back"
                    }
                    default {
                        $hResult = @{}
                    }
                }
            } else {
                $bResultOK = $true
            }
        }

        return $hResult
    }
}

function Read-CertObjectAndSAN {
    [CmdletBinding()]
    Param(
        [hashtable]$PreviousValues,
        [switch]$AllowBack
    )
    $sFreeStringRegex = "^$|^[0-9a-zA-Zéèàùêëîï _.-]+$"
    $hCertProps = [ordered]@{
        CommonName = @{regex = "^[0-9a-zA-Z ._*-]+$"}
        Organisation = @{regex = $sFreeStringRegex}
        OrganisationalUnit = @{regex = $sFreeStringRegex}
        Locality = @{regex = $sFreeStringRegex}
        State = @{regex = $sFreeStringRegex}
        CountryCode = @{regex = "^$|^..$"}
    }
    $sIPRegex = Get-IPRegex -FullLine
    $sDNSRegex = Get-DNSRegex -FullLine -AllowWildcard
    $sSANTextBoxName = "SAN"

    $hPreviousCertObj = if ($PreviousValues -and $PreviousValues.CertificateObject) { $PreviousValues.CertificateObject } else { @{} }
    $hPreviousSAN = if ($PreviousValues -and $PreviousValues.SAN) { $PreviousValues.SAN } else { @{} }
    $sDefaultSAN = if ($hPreviousSAN.SANdns -or $hPreviousSAN.SANipaddress) {
        ((@($hPreviousSAN.SANdns) + @($hPreviousSAN.SANipaddress)) | Where-Object { $_ }) -join "`n"
    } else { "" }

    $cSeparator = [System.ConsoleColor]::Blue
    $cHeader = Get-CLIDialogTheme "HeaderForegroundColor"
    $cHint = Get-CLIDialogTheme "HintColor"

    $aDialogLines = @()
    $aDialogLines += New-CLIDialogSeparator -AutoLength -Text "Please enter certificate object" -ForegroundColor $cSeparator
    foreach ($k in $hCertProps.Keys) {
        $hTB = @{
            Header = $k
            Name = $k
            HeaderAlign = "Left"
            Prefix = "  "
            FocusedPrefix = "> "
            HeaderForegroundColor = $cHeader
            Regex = $hCertProps[$k].regex
        }
        if ($hPreviousCertObj.$k) { $hTB.Text = [string]$hPreviousCertObj.$k }
        $aDialogLines += New-CLIDialogTextBox @hTB
    }

    $aDialogLines += New-CLIDialogSeparator -AutoLength -Text "Subject Alternative Names" -ForegroundColor $cSeparator
    $aDialogLines += New-CLIDialogText -Text "Enter DNS names and IP addresses, one per line." -ForegroundColor $cHint -AddNewLine

    $sbSANValidation = {
        param($text)
        foreach ($sLine in $text.Split("`n")) {
            $sTrim = $sLine.Trim()
            if ($sTrim.Length -gt 0 -and $sTrim -notmatch $sIPRegex -and $sTrim -notmatch $sDNSRegex) {
                return $false
            }
        }
        return $true
    }.GetNewClosure()

    $hSANTB = @{
        Header = "DNS / IP"
        Name = $sSANTextBoxName
        MultiLine = $true
        VisibleLines = 4
        Prefix = "  "
        FocusedPrefix = "> "
        HeaderForegroundColor = $cHeader
        ValidationScript = $sbSANValidation
        ValidationErrorReason = "each line must be a valid DNS name or IP address"
    }
    if ($sDefaultSAN) { $hSANTB.Text = $sDefaultSAN }
    $aDialogLines += New-CLIDialogTextBox @hSANTB

    $aDialogLines += New-CLIDialogSeparator -AutoLength -ForegroundColor $cSeparator
    $aButtons = @(New-CLIDialogButton -Text "&Ok" -Validate)
    if ($AllowBack) { $aButtons += New-CLIDialogButton -Text "&Back" -Back }
    $aDialogLines += New-CLIDialogObjectsRow -Header " " -Prefix "  " -FocusedPrefix "> " -HeaderSeparator "  " -Row $aButtons

    $oDialogResult = Invoke-CLIDialog -InputObject $aDialogLines -Validate -ErrorDetails
    if ($oDialogResult.Action -eq "Back") {
        return New-DialogResultAction -Action "Back"
    }
    if ($oDialogResult.Action -ne "Validate") {
        return $null
    }

    $hFormValues = $oDialogResult.DialogResult.Form.GetValue($true)
    $hCertObject = [ordered]@{}
    foreach ($k in $hCertProps.Keys) {
        $hCertObject[$k] = $hFormValues[$k]
    }

    $aSANLines = $hFormValues[$sSANTextBoxName].Split("`n") |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_.Length -gt 0 }
    $aDNS = @()
    $aIP = @()
    foreach ($sLine in $aSANLines) {
        if ($sLine -match $sIPRegex) {
            $aIP += $sLine
        } elseif ($sLine -match $sDNSRegex) {
            $aDNS += $sLine
        }
    }

    $sCN = $hCertObject.CommonName
    if ($sCN -and ($aDNS -notcontains $sCN)) {
        $sAnswer = Invoke-YesNoCLIDialog -Message "The Common Name of the certificate ($sCN) should be in subject alternative names" `
                                         -Vertical -YN -YesButtonText "Include in DNS SAN" `
                                         -NoButtonText "Do not include in SAN"
        if ($sAnswer -eq "Yes") { $aDNS += $sCN }
    }

    $hSAN = @{}
    if ($aDNS.Count -gt 0) { $hSAN.SANdns = $aDNS }
    if ($aIP.Count -gt 0) { $hSAN.SANipaddress = $aIP }

    return @{
        CertificateObject = $hCertObject
        SAN = $hSAN
    }
}

function Import-CertToFormValues {
    $oDialogResult = Read-CLIDialogValidatedValue `
        -Header "Enter a certificate file path, an HTTPS URL, or a host[:port] to import" `
        -PropertyName "Path / URL / Host" `
        -ValidationMethod { param($v) return ($v.Trim().Length -gt 0) } `
        -ErrorMessage "Value cannot be empty" `
        -AllowCancel

    if ($null -eq $oDialogResult) { return $null }
    if ($oDialogResult.PSTypeNames -and $oDialogResult.PSTypeNames[0] -like "DialogResult.Action.*") {
        return $oDialogResult
    }
    $sInput = if ($oDialogResult.PSTypeNames -and $oDialogResult.PSTypeNames[0] -eq "DialogResult.Value") {
        $oDialogResult.Value
    } else {
        [string]$oDialogResult
    }
    $sInput = $sInput.Trim().Trim('"').Trim("'")

    $sHttpsUrlRegex = '^https://.+'
    $sHostPortRegex = Get-HostPortRegex -FullLine

    $oCert = $null
    try {
        if ($sInput -match $sHttpsUrlRegex) {
            Write-Host "Fetching certificate from $sInput ..." -ForegroundColor Cyan
            $oCert = Get-CertificateFromUrl -Url $sInput
        } elseif (Test-Path -LiteralPath $sInput -PathType Leaf) {
            $oCert = Get-CertificateFromFile -Path $sInput
        } elseif ($sInput -match $sHostPortRegex) {
            $sUrl = "https://$sInput"
            Write-Host "Fetching certificate from $sUrl ..." -ForegroundColor Cyan
            $oCert = Get-CertificateFromUrl -Url $sUrl
        } else {
            $oCert = Get-CertificateFromFile -Path $sInput
        }
    } catch {
        Write-Host "Failed to load certificate: $_" -ForegroundColor Red
        return $null
    }
    if (-not $oCert) { return $null }

    Write-Host "Imported certificate subject: $($oCert.Subject)" -ForegroundColor Green

    $hDN = ConvertFrom-X500DistinguishedName -DistinguishedName $oCert.Subject
    $hCertObj = [ordered]@{
        CommonName         = if ($hDN.Contains("CN")) { $hDN.CN } else { "" }
        Organisation       = if ($hDN.Contains("O"))  { $hDN.O }  else { "" }
        OrganisationalUnit = if ($hDN.Contains("OU")) { $hDN.OU } else { "" }
        Locality           = if ($hDN.Contains("L"))  { $hDN.L }  else { "" }
        State              = if ($hDN.Contains("S"))  { $hDN.S }  elseif ($hDN.Contains("ST")) { $hDN.ST } else { "" }
        CountryCode        = if ($hDN.Contains("C"))  { $hDN.C }  else { "" }
    }

    $hSANByType = Get-CertificateSAN -Certificate $oCert
    $hSAN = @{}
    if ($hSANByType.Contains("DNS_NAME") -and $hSANByType.DNS_NAME.Count -gt 0) {
        $hSAN.SANdns = @($hSANByType.DNS_NAME)
    }
    if ($hSANByType.Contains("IP_ADDRESS") -and $hSANByType.IP_ADDRESS.Count -gt 0) {
        $hSAN.SANipaddress = @($hSANByType.IP_ADDRESS)
    }

    return @{
        CertAndSAN = @{
            CertificateObject = $hCertObj
            SAN = $hSAN
        }
    }
}

function Read-CSR {
    Param(
        [switch]$ItemsMode,
        [hashtable]$InitialValues
    )
    $aCertAndSANSteps = @(if ($ItemsMode) {
        New-CLIDialogWizardStep -PropertyName "CertAndSAN" -ScriptBlock {
            param($result)
            return Read-CertObjectAndSAN -PreviousValues $result.CertAndSAN -AllowBack
        }
    } else {
        New-CLIDialogWizardStep -PropertyName "CertificateObject" -ScriptBlock {
            param($result)
            $sPreviousDN = if ($result.CertificateObject) { $result.CertificateObject.Subject } else { "" }
            $oResult = Read-CLIDialogDN -Header "Please enter certificate object as DN format" -AllowBack -DefaultValue $sPreviousDN
            if ($null -ne $oResult -and $oResult.PSTypeNames -and $oResult.PSTypeNames[0] -eq "DialogResult.Action.Back") {
                return $oResult
            }
            return [ordered]@{Subject = $oResult}
        }
        New-CLIDialogWizardStep -PropertyName "SAN" -ScriptBlock {
            param($result)
            $hPreviousSAN = if ($result.SAN -and ($result.SAN.SANdns -or $result.SAN.SANipaddress)) { $result.SAN } else { $null }
            return Read-SAN -CommonName $result.CertificateObject.CommonName -AskForValidation -AllowBack -PreviousValues $hPreviousSAN
        }
    })
    $steps = $aCertAndSANSteps + @(
        New-CLIDialogWizardStep -PropertyName "CA" -ScriptBlock {
            param($result)
            $sDefaultCA = if ($result.CA -and $result.CA.PSObject.TypeNames[0] -eq "ADcertificationAuthority") { $result.CA.Name } else { "" }
            if ($ScriptConfig.CAFilter -and ($ScriptConfig.CAFilter -ne "")) {
                return Read-CA $ScriptConfig.CAFilter -DefaultCAName $sDefaultCA
            } else {
                return Read-CA -DefaultCAName $sDefaultCA
            }
        }
        New-CLIDialogWizardStep -PropertyName "Template" -ScriptBlock {
            param($result)
            $sDefaultTemplate = if ($result.Template -and $result.Template.CertificateTemplate) { $result.Template.CertificateTemplate } else { "" }
            if (($null -ne $result.CA) -and ($result.CA.PSObject.TypeNames[0] -eq "ADcertificationAuthority")) {
                if ($ScriptConfig.TemplateFilter -and ($ScriptConfig.TemplateFilter -ne "")) {
                    return Read-TemplateName -CA $result.CA.Name -TemplateFilter $ScriptConfig.TemplateFilter -DefaultTemplateName $sDefaultTemplate
                } else {
                    return Read-TemplateName -CA $result.CA.Name -DefaultTemplateName $sDefaultTemplate
                }
            }
            return @{}
        }
        New-CLIDialogWizardStep -PropertyName "KeyPassword" -ScriptBlock {
            param($result)
            $sPreviousPwd = if ($result.KeyPassword -and $result.KeyPassword.KeyPassword) { $result.KeyPassword.KeyPassword } else { $null }
            return Read-KeyPassword -AllowBack -DefaultValue $sPreviousPwd
        }
        New-CLIDialogWizardStep -PropertyName "FileNames" -ScriptBlock {
            param($result)
            $sPreviousName = if ($result.FileNames -and $result.FileNames.FriendlyName) {
                $result.FileNames.FriendlyName
            } elseif ($result.CertAndSAN -and $result.CertAndSAN.CertificateObject.CommonName) {
                $result.CertAndSAN.CertificateObject.CommonName
            } elseif ($result.CertificateObject -and $result.CertificateObject.Subject -match "CN=([^,]+)") {
                $matches[1]
            } else {
                ""
            }
            return Read-FileNames -DefaultFriendlyName $sPreviousName -AllowBack
        }
    )

    $oWizardResult = Invoke-CLIDialogWizard -Steps $steps -InitialObject $InitialValues

    # Handle Back/Exit
    if ($oWizardResult.PSTypeNames -and $oWizardResult.PSTypeNames[0] -like "DialogResult.Action.*") {
        return $oWizardResult
    }

    # Build the CSR hashtable from wizard results
    $hCSR = @{}
    if ($ItemsMode) {
        $hCSR += $oWizardResult.CertAndSAN.CertificateObject
        $hCSR += $oWizardResult.CertAndSAN.SAN
    } else {
        $hCSR += $oWizardResult.CertificateObject
        $hCSR += $oWizardResult.SAN
    }
    if ($oWizardResult.Template.Count -gt 0) {
        $hCSR += $oWizardResult.Template
    }
    $hCSR += $oWizardResult.KeyPassword
    $hCSR += $oWizardResult.FileNames

    $hMoreInfo = if (($null -ne $oWizardResult.CA) -and ($oWizardResult.CA.PSObject.TypeNames[0] -eq "ADcertificationAuthority")) {
        $sPKIServer = (Get-CAEnrollmentServices -NameFilter ("^" + $oWizardResult.CA.Name + "$")).DNSHostName
        @{
            PKIServer = $sPKIServer
            CAName = $oWizardResult.CA.Name
        }
    } else {
        @{
            PKIServer = ""
            CAName = ""
        }
    }

    return @{
        CSR = $hCSR
        MoreInfo = $hMoreInfo
    }
}

function New-CSR_CLI {
    Param(
        [string]$OpenSSLPath,
        [switch]$ItemsMode,
        [hashtable]$InitialValues
    )
    $oCSR = Read-CSR -ItemsMode:$ItemsMode -InitialValues $InitialValues
    if ($oCSR.PSObject.TypeNames[0] -eq "DialogResult.Action.Back") {
        return $oCSR
    }
    $hCSR = $oCSR.CSR
    $hMoreInfo = $oCSR.MoreInfo
    $hMoreInfo.Add("FolderName", $hCSR.FolderName)
    $hMoreInfo.Add("FriendlyName", $hCSR.FriendlyName)
    $hMoreInfo.Add("SafeName", $hCSR.SafeName)
    $hCSR.Remove("FolderName")
    $hCSR.Remove("FriendlyName")
    $hCSR.Remove("SafeName")
    $sWorkingDir = (Get-ScriptDir -WorkingDir)
    $sCertFolder = $sWorkingDir + "\" + $hMoreInfo.FolderName
    Save-CertInfo -CertFolder $sCertFolder -CertInfo @{ CSR = $hCSR; MoreInfo = $hMoreInfo }
    New-OpenSSLCSR @hCSR -OpenSSLPath $OpenSSLPath | Out-String | Write-Host
    $oResult = [pscustomobject]@{
        CSR = $hCSR
        MoreInfo = $hMoreInfo
        Folder = $sWorkingDir + "\" + $hMoreInfo.FolderName
    }
    return $oResult
}

function Select-CertFolder {
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$Message,
        [switch]$AllowBack
    )
    $sWorkingDir = (Get-ScriptDir -WorkingDir)
    $oFolder = Select-CLIFileFromFolder -Path $sWorkingDir -Filter "*" -ColumnName "Name" -SeparatorColor Blue -SelectHeaderMessage $Message -AllowBack:$AllowBack
    if ($oFolder.PSTypeNames -and $oFolder.PSTypeNames[0] -like "DialogResult.Action.*") {
        return $oFolder
    }
    return $oFolder.Value.FullName
}

function Send-CSRToCA_CLI {
    Param(
        [string]$CertFolder,
        [object]$CSRConfig,
        [object]$CSRMoreInfo
    )
    $sCertFolder = if ($CertFolder) {
        $CertFolder
    } else {
        Select-CertFolder -Message "Which CSR do you want to send to CA?" -AllowBack
    }
    if ($sCertFolder.PSTypeNames -and $sCertFolder.PSTypeNames[0] -like "DialogResult.Action.*") { return }
    $oCertInfo = if ($CSRConfig -and $CSRMoreInfo) { $null } else { Get-CertInfo -CertFolder $sCertFolder }
    $hCSRConfig = if ($CSRConfig) { $CSRConfig } elseif ($oCertInfo) { $oCertInfo.CSR } else { $null }
    $hCSRMoreInfo = if ($CSRMoreInfo) { $CSRMoreInfo } elseif ($oCertInfo) { $oCertInfo.MoreInfo } else { $null }
    #$sPKICSRFolder = Get-PKICSRFolder -PKIServer $hCSRMoreInfo.PKIServer
    $hSubmitCSR = @{
        #CSRPath = ($sPKICSRFolder + (Split-Path $hCSRConfig.CSROutPath -Leaf))
        CSRContent = Get-Content -Path $hCSRConfig.CSROutPath -Raw
        #PKIServer = $hCSRMoreInfo.PKIServer
        CAName = $hCSRMoreInfo.CAName
    }
    if (Connect-PKIServer -PKIServer $hCSRMoreInfo.PKIServer -Verbose) {
        #Copy-Item -Path $hCSRConfig.CSROutPath -Destination $sPKICSRFolder -ToSession $Global:PKISession
        $oResult = Send-CSRToCA @hSubmitCSR -Session $Global:PKISession
        if ($oResult.Success) { 
            Write-Host "CSR sent successfully!"
            Write-Host "RequestID: $($oResult.RequestID)"
        } else {
            Write-Host "Failed to submit CSR"
            Write-Host "Reason:"
            Write-Host $oResult.Output
        }
        $oCertInfoToSave = if ($oCertInfo) { $oCertInfo } else { @{ CSR = $hCSRConfig; MoreInfo = $hCSRMoreInfo } }
        $oCertInfoToSave | Add-Member -NotePropertyName "CSRSubmitted" -NotePropertyValue $oResult -Force
        Save-CertInfo -CertFolder $sCertFolder -CertInfo $oCertInfoToSave
        $hSubmitCSR.Result = $oResult
        return $hSubmitCSR
    } else {
        Write-Error "Can't connect to PKI server"
    }
}

function Read-MissingJsonInfo {
    $hHashtableParams = [ordered]@{
        "Request ID" = @{regex = "^[0-9]+$"}
        "PKI server name" = @{regex = "^[A-Za-z0-9_.-]+$"}
        "CA Name" = @{regex = "[A-Za-z0-9_. -]+"}
    }
    return Read-CLIDialogHashtable -Properties $hHashtableParams -Header "Can't find request ID and CA Name in the json files. Please enter missing info:"
}

function Invoke-IssueCSR_CLI {
    Param(
        [string]$CertFolder,
        [string]$RequestID,
        [string]$PKIServer,
        [string]$CAName
    )
    $sCertFolder = if ($CertFolder) {
        $CertFolder
    } else {
        Select-CertFolder -Message "Which certificate do you want to issue?" -AllowBack
    }
    if ($sCertFolder.PSTypeNames -and $sCertFolder.PSTypeNames[0] -like "DialogResult.Action.*") { return }
    $sRequestID, $sPKIServer, $sCAName = if ($RequestID -and $PKIServer -and $CAName) {
        $RequestID, $PKIServer, $CAName
    } else {
        $oCertInfo = Get-CertInfo -CertFolder $sCertFolder
        if ($oCertInfo -and $oCertInfo.CSRSubmitted -and $oCertInfo.MoreInfo) {
            $oCertInfo.CSRSubmitted.RequestID, $oCertInfo.MoreInfo.PKIServer, $oCertInfo.MoreInfo.CAName
        } else {
            $hMissingInfo = Read-MissingJsonInfo
            $hMissingInfo."Request ID"
            $hMissingInfo."PKI server name"
            $hMissingInfo."CA Name"
        }
    }
    if (Connect-PKIServer -PKIServer $sPKIServer) {
        $oResult = Sign-CSR -Session $Global:PKISession -RequestID $sRequestID -CAName $sCAName
        if ($oResult.Success) {
            Write-Host "Certificate issued successfully."
        } else {
            Write-Host "Certificate issue failed."
            Write-Host "Reason:"
            Write-host $oResult.Output
        }
        return $oResult
    } else {
        Write-Error "Can't connect to PKI server"
    }
}

function Connect-PKIServer {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory)]
        [string]$PKIServer
    )
    $oResult = Connect-CLIDialogPSSession -ComputerName $PKIServer -Credential $Global:PKICredential -Session $Global:PKISession -Message "Please provide credentials to connect to" -AllowCancel
    if ($oResult -and $oResult.PSTypeNames[0] -notlike "DialogResult.Action.*") {
        $Global:PKICredential = $oResult.Credential
        $Global:PKISession = $oResult.Session
        return $true
    }
    return $false
}

function Get-CertificateNameFromFolder {
    Param(
        [Parameter(Mandatory, Position = 0)]
        [string]$FolderName
    )
    $sRegex = "^(?<dns>$(Get-DNSRegex))_[0-9]{4,4}(0[1-9]|1[0-2])(0[1-9]|1[0-9]|2[0-9]|30|31)-((0|1)[0-9]|2[0-3])[0-5][0-9][0-5][0-9]$"
    $ss = Select-String -InputObject $FolderName -Pattern $sRegex -AllMatches
    if ($ss) {
        return ($ss.Matches.Groups | Where-Object { $_.Name -eq "dns" }).Value
    } else {
        return $FolderName
    }
}

function Get-IssuedCertificate_CLI {
    Param(
        [string]$CertFolder,
        [string]$RequestID,
        [string]$PKIServer,
        [string]$CAName
    )
    $sCertFolder = if ($CertFolder) {
        $CertFolder
    } else {
        Select-CertFolder -Message "Which certificate do you want to retreive from PKI server?" -AllowBack
    }
    if ($sCertFolder.PSTypeNames -and $sCertFolder.PSTypeNames[0] -like "DialogResult.Action.*") { return }
    $oCertInfo = Get-CertInfo -CertFolder $sCertFolder
    $sRequestID, $sPKIServer, $sCAName = if ($RequestID -and $PKIServer -and $CAName) {
        $RequestID, $PKIServer, $CAName
    } elseif ($oCertInfo -and $oCertInfo.CSRSubmitted -and $oCertInfo.MoreInfo) {
        $oCertInfo.CSRSubmitted.RequestID, $oCertInfo.MoreInfo.PKIServer, $oCertInfo.MoreInfo.CAName
    } else {
        $hMissingInfo = Read-MissingJsonInfo
        $hMissingInfo."Request ID"
        $hMissingInfo."PKI server name"
        $hMissingInfo."CA Name"
    }
    # File base name must be file-system safe: prefer the stored SafeName, fall back to a
    # sanitized FriendlyName (older CertInfo), then to the folder-derived name.
    $sCertName = if ($oCertInfo -and $oCertInfo.MoreInfo.SafeName) {
        $oCertInfo.MoreInfo.SafeName
    } elseif ($oCertInfo -and $oCertInfo.MoreInfo.FriendlyName) {
        ConvertTo-SafeFileName -Name $oCertInfo.MoreInfo.FriendlyName
    } else {
        $sCertFolderName = $sCertFolder.Substring($sCertFolder.LastIndexOf("\") + 1)
        Get-CertificateNameFromFolder -FolderName $sCertFolderName
    }
    if (Connect-PKIServer -PKIServer $sPKIServer) {
        $sOutCer = $sCertFolder + "\" + $sCertName + ".cer"
        $sOutCertChain = $sCertFolder + "\" + $sCertName + ".p7b"
        #$sPKIWorkFolder = Get-PKICSRFolder -PKIServer $sPKIServer
        #$oResult = Get-IssuedCertificate -Session $Global:PKISession -RequestID $sRequestID -CAName $sCAName -CertOut $sOutCer -CertChainOut $sOutCertChain -PKIWorkFolder $sPKIWorkFolder
        $oResult = Get-IssuedCertificate -Session $Global:PKISession -RequestID $sRequestID -CAName $sCAName -CertOut $sOutCer -CertChainOut $sOutCertChain
        if ($oResult.Success) {
            Write-Host "Certificate retrieved successfully."
            Write-Host "Cert file = $($oResult.Cert)"
            Write-Host "Cert chain file = $($oResult.CertChain)"
        } else {
            Write-Host "Certificate retrieve failed."
            Write-Host "Reason:"
            Write-host $oResult.Output
        }
        return $oResult
    } else {
        Write-Error "Can't connect to PKI server"
    }
}

function New-PFX_CLI {
    [CmdletBinding()]
    Param(
        [string]$OpenSSLPath,
        [securestring]$PrivateKeyPassword,
        [string]$CertFolder
    )
    $sCertFolder = if ($CertFolder) {
        $CertFolder
    } else {
        Select-CertFolder -Message "For which certificate do you want to build a PFX?" -AllowBack
    }
    if ($sCertFolder.PSTypeNames -and $sCertFolder.PSTypeNames[0] -like "DialogResult.Action.*") { return }
    $oCertInfo = Get-CertInfo -CertFolder $sCertFolder
    # File base name must be file-system safe: prefer the stored SafeName, fall back to a
    # sanitized FriendlyName (older CertInfo), then to the folder-derived name.
    $sCertName = if ($oCertInfo -and $oCertInfo.MoreInfo.SafeName) {
        $oCertInfo.MoreInfo.SafeName
    } elseif ($oCertInfo -and $oCertInfo.MoreInfo.FriendlyName) {
        ConvertTo-SafeFileName -Name $oCertInfo.MoreInfo.FriendlyName
    } else {
        $sCertFolderName = $sCertFolder.Substring($sCertFolder.LastIndexOf("\") + 1)
        Get-CertificateNameFromFolder -FolderName $sCertFolderName
    }
    $sKeyFile = $sCertFolder + "\" + $sCertName + ".key"
    if (-not (Test-Path $sKeyFile -PathType Leaf)) {
        Write-Error "Private key file not found: $sKeyFile"
        return
    }
    $sOutPFXFile = $sCertFolder + "\" + $sCertName + ".pfx"

    # Three-tier detection:
    #   1. canonical PKI bundle <name>.p7b — sufficient on its own
    #   2. otherwise scan the folder for any .cer/.crt files
    #   3. otherwise ask the user for the cert files via a multi-line prompt
    $sP7BFile = "$sCertFolder\$sCertName.p7b"
    $aCertFiles = if (Test-Path -LiteralPath $sP7BFile -PathType Leaf) {
        Write-Host "Using PKI bundle: $sP7BFile" -ForegroundColor Cyan
        @($sP7BFile)
    } else {
        $aFolderCertFiles = @(Get-ChildItem -Path "$sCertFolder\*" -Include "*.cer", "*.crt" -File |
            Where-Object { $_.Name -notlike "*.p7b.cer" } |
            ForEach-Object { $_.FullName })
        if ($aFolderCertFiles.Count -gt 0) {
            Write-Host "Using certificate files found in $sCertFolder :" -ForegroundColor Cyan
            foreach ($f in $aFolderCertFiles) { Write-Host "  $f" }
            $aFolderCertFiles
        } else {
            Write-Host "No certificate files found in $sCertFolder." -ForegroundColor Yellow
            $oArr = Read-CLIDialogArray `
                -Header "Certificate files for PFX generation" `
                -TextBoxHeader "Path" `
                -HintMessage "Enter one path per line. CER/CRT/P7B accepted, in any order. Surrounding quotes are stripped." `
                -VisibleLines 6 `
                -ValidationScript {
                    param($line)
                    $p = $line.Trim().Trim('"').Trim("'")
                    return ($p.Length -gt 0 -and (Test-Path -LiteralPath $p -PathType Leaf))
                } `
                -AllowCancel
            if ($null -eq $oArr -or ($oArr.PSTypeNames -and $oArr.PSTypeNames[0] -like "DialogResult.Action.*")) { return }
            @($oArr | ForEach-Object { $_.Trim().Trim('"').Trim("'") } | Where-Object { $_.Length -gt 0 })
        }
    }

    if ($aCertFiles.Count -eq 0) {
        Write-Host "No certificate files provided. Aborting." -ForegroundColor Red
        return
    }

    $ssKeyPassword = if ($PrivateKeyPassword) {
        $PrivateKeyPassword
    } else {
        Read-Host -AsSecureString -Prompt "Please enter private key password"
    }
    $sWindowsPFX = Invoke-YesNoCLIDialog -YN -Message "Will this PFX be used in the Windows certificate store?"

    $hMergeOptions = @{
        PrivateKey       = $sKeyFile
        CertificateFiles = $aCertFiles
        IncludeOSStore   = $true
        OutPFXFile       = $sOutPFXFile
        OpenSSLPath      = $OpenSSLPath
        PFXPassword      = $ssKeyPassword
        KeyPassword      = $ssKeyPassword
        FriendlyName     = if ($oCertInfo -and $oCertInfo.MoreInfo.FriendlyName) { $oCertInfo.MoreInfo.FriendlyName } else { $sCertName }
        WindowsPFX       = ($sWindowsPFX -eq "Yes")
    }

    try {
        Merge-OpenSSLPFX @hMergeOptions
    } catch {
        Write-Host "PFX generation failed: $_" -ForegroundColor Red
        return
    }

    if (Test-Path $sOutPFXFile) {
        Write-Host "PFX generated successfully:" -ForegroundColor Green
        Write-Host $sOutPFXFile
        Write-Host ""
    } else {
        Write-Host "PFX generation failed" -ForegroundColor Red
        Write-Host ""
    }
}

function New-PKISignedCertAndPFX_CLI {
    Param(
        [string]$OpenSSLPath,
        [switch]$ItemsMode,
        [hashtable]$InitialValues
    )
    $oCSR = New-CSR_CLI -OpenSSLPath $OpenSSLPath -ItemsMode:$ItemsMode -InitialValues $InitialValues
    if ($oCSR.PSObject.TypeNames[0] -eq "DialogResult.Action.Back") {
        return $oCSR
    }
    $Global:oCSR = $oCSR
    Write-Host "-------------------------- Send-CSRToCA -------------------------" -ForegroundColor Blue
    $oSubmittedCSR = Send-CSRToCA_CLI -CertFolder $oCSR.Folder -CSRConfig $oCSR.CSR -CSRMoreInfo $oCSR.MoreInfo
    $Global:oSubmittedCSR = $oSubmittedCSR
    if ($oSubmittedCSR.Result.Success) {
        Write-Host "------------------------ Invoke-IssueCSR ------------------------" -ForegroundColor Blue
        $oIssuedCertInfo = Invoke-IssueCSR_CLI -CertFolder $oCSR.Folder -RequestID $oSubmittedCSR.Result.RequestID -PKIServer $oSubmittedCSR.PKIServer -CAName $oSubmittedCSR.CAName
        $Global:oIssuedCertInfo = $oIssuedCertInfo
        if ($oIssuedCertInfo.Success) {
            Write-Host "--------------------- Get-IssuedCertificate ---------------------" -ForegroundColor Blue
            $oRetrievedCertInfo = Get-IssuedCertificate_CLI -CertFolder $oCSR.Folder -RequestID $oSubmittedCSR.Result.RequestID -PKIServer $oSubmittedCSR.PKIServer -CAName $oSubmittedCSR.CAName
            $Global:oRetrievedCertInfo = $oRetrievedCertInfo
            if ($oRetrievedCertInfo.Success) {
                Write-Host "-------------------------- New-PFX_CLI --------------------------" -ForegroundColor Blue
                New-PFX_CLI -OpenSSLPath $OpenSSLPath -PrivateKeyPassword $oCSR.CSR.KeyPassword -CertFolder $oCSR.Folder
                Write-Host "-----------------------------------------------------------------" -ForegroundColor Blue
            } else {
                Write-Host "Failed to get issued certificate" -ForegroundColor Red
                Write-Host "Reason:"
                Write-Host $oRetrievedCertInfo.Output
            }
        } else {
            Write-Host "Failed to issue certificate" -ForegroundColor Red
            Write-Host "Reason:"
            Write-Host $oSubmittedCSR.Output
        }
    } else {
        Write-Host "CSR submission failed" -ForegroundColor Red
        Write-Host "Reason:"
        Write-Host $oSubmittedCSR.Result.Output
    }
}

function Invoke-ImportCertFlow_CLI {
    Param(
        [string]$OpenSSLPath
    )
    while ($true) {
        $oImported = Import-CertToFormValues
        if ($null -eq $oImported) { return }
        if ($oImported.PSTypeNames -and $oImported.PSTypeNames[0] -like "DialogResult.Action.*") { return }
        $oResult = New-PKISignedCertAndPFX_CLI -OpenSSLPath $OpenSSLPath -ItemsMode -InitialValues $oImported
        if (-not ($oResult -and $oResult.PSTypeNames -and $oResult.PSTypeNames[0] -eq "DialogResult.Action.Back")) {
            return
        }
    }
}

function Invoke-ImportCSRFlow_CLI {
    Param(
        [string]$OpenSSLPath
    )
    while ($true) {
        $oImported = Import-CertToFormValues
        if ($null -eq $oImported) { return }
        if ($oImported.PSTypeNames -and $oImported.PSTypeNames[0] -like "DialogResult.Action.*") { return }
        $oResult = New-CSR_CLI -OpenSSLPath $OpenSSLPath -ItemsMode -InitialValues $oImported
        if (-not ($oResult -and $oResult.PSTypeNames -and $oResult.PSTypeNames[0] -eq "DialogResult.Action.Back")) {
            return
        }
    }
}

function Get-ThisScriptConfigPath {
    return (Get-ScriptDir -InputDir) + "\config.json"
}

function Get-ThisScriptConfig {
    $sPath = Get-ThisScriptConfigPath
    if (Test-Path $sPath -PathType Leaf) {
        return Get-Content -Path $sPath | ConvertFrom-Json
    }
    return [PSCustomObject]@{ CAFilter = ""; TemplateFilter = "" }
}

function Edit-ScriptConfig {
    $hProperties = [ordered]@{
        "CAFilter" = @{ Text = $ScriptConfig.CAFilter }
        "TemplateFilter" = @{ Text = $ScriptConfig.TemplateFilter }
    }
    $oResult = Read-CLIDialogHashtable -Properties $hProperties -Header "Script configuration" -AllowCancel
    if ($null -ne $oResult) {
        $ScriptConfig.CAFilter = $oResult.CAFilter
        $ScriptConfig.TemplateFilter = $oResult.TemplateFilter
        $ScriptConfig | ConvertTo-Json -Depth 10 | Out-File (Get-ThisScriptConfigPath) -Encoding utf8
        Write-Host "Configuration saved." -ForegroundColor Green
        Write-Host ""
    }
}

function Read-PFXConversionOptions {
    Param(
        [switch]$AllowBack
    )
    $cSep = [System.ConsoleColor]::Blue
    $cHint = Get-CLIDialogTheme "HintColor"

    $aLines = @()
    $aLines += New-CLIDialogSeparator -AutoLength -Text "Output container" -ForegroundColor $cSep
    $aLines += New-CLIDialogObjectsRow -Name "Container" -Header "Container" -MandatoryRadioButtonValue -Row @(
        New-CLIDialogRadioButton -Text "&PFX" -Enabled $true -Object "PFX"
        New-CLIDialogRadioButton -Text "PEM co&mbined" -Enabled $false -Object "PEMCombined"
        New-CLIDialogRadioButton -Text "PEM &separate" -Enabled $false -Object "PEMSeparate"
        New-CLIDialogRadioButton -Text "&DER (cert only)" -Enabled $false -Object "DER"
    )

    $aLines += New-CLIDialogSeparator -AutoLength -Text "Include" -ForegroundColor $cSep
    $aLines += New-CLIDialogCheckBox -Name "IncludeChain" -Text "Chain (&intermediates)" -Enabled $true -AddNewLine
    $aLines += New-CLIDialogCheckBox -Name "IncludeRoot"  -Text "&Root CA" -Enabled $false -AddNewLine
    $aLines += New-CLIDialogCheckBox -Name "IncludeKey"   -Text "Private &key (PEM only)" -Enabled $true -AddNewLine

    $aLines += New-CLIDialogSeparator -AutoLength -Text "Private key" -ForegroundColor $cSep
    $aLines += New-CLIDialogObjectsRow -Name "KeyFormat" -Header "Format    " -MandatoryRadioButtonValue -Row @(
        New-CLIDialogRadioButton -Text "PKCS#&8" -Enabled $true -Object "PKCS8"
        New-CLIDialogRadioButton -Text "PKCS#&1 (RSA)" -Enabled $false -Object "PKCS1"
    )
    $aLines += New-CLIDialogObjectsRow -Name "Protection" -Header "Protection" -MandatoryRadioButtonValue -Row @(
        New-CLIDialogRadioButton -Text "&Encrypted (password)" -Enabled $true -Object "Encrypt"
        New-CLIDialogRadioButton -Text "&Unencrypted" -Enabled $false -Object "Plain"
    )

    $aLines += New-CLIDialogText -Text "An unencrypted private key (or a PFX without password) will be stored inside a password-protected ZIP." -ForegroundColor $cHint -AddNewLine

    $aLines += New-CLIDialogSeparator -AutoLength -ForegroundColor $cSep
    $aButtons = @(New-CLIDialogButton -Text "&Ok" -Validate)
    if ($AllowBack) { $aButtons += New-CLIDialogButton -Text "&Back" -Back }
    $aLines += New-CLIDialogObjectsRow -Header " " -Prefix "  " -FocusedPrefix "> " -HeaderSeparator "  " -Row $aButtons

    $oDialogResult = Invoke-CLIDialog -InputObject $aLines -Validate -ErrorDetails
    if ($oDialogResult.Action -eq "Back") { return New-DialogResultAction -Action "Back" }
    if ($oDialogResult.Action -ne "Validate") { return $null }

    $hForm = $oDialogResult.DialogResult.Form.GetValue($true)
    return @{
        Container    = $hForm["Container"]
        IncludeChain = [bool]$hForm["IncludeChain"]
        IncludeRoot  = [bool]$hForm["IncludeRoot"]
        IncludeKey   = [bool]$hForm["IncludeKey"]
        KeyFormat    = $hForm["KeyFormat"]
        Protection   = $hForm["Protection"]
    }
}

function Convert-Certificate_CLI {
    Param(
        [string]$OpenSSLPath
    )

    function Remove-FileSecure {
        Param([string]$Path)
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            try {
                $len = (Get-Item -LiteralPath $Path).Length
                if ($len -gt 0) { [System.IO.File]::WriteAllBytes($Path, (New-Object byte[] $len)) }
            } catch {}
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        }
    }

    # 1. Select the source PFX: every *.pfx found in the working folders, plus a "Select
    #    Another File" option (AllowOtherFile) to pick an external PFX. An external file is
    #    copied into a new working subfolder named "<pfx>_<date>", which then becomes the
    #    working folder for the rest of the flow; a file already in the working tree is used
    #    in place (its own folder is the working folder).
    $sWorkingDir = Get-ScriptDir -WorkingDir
    $oSel = Select-CLIFileFromFolder -Path $sWorkingDir -Filter "*.pfx" -Recurse -ColumnName "Folder" -AllowOtherFile -AllowBack `
        -SelectHeaderMessage "Select the PFX to convert (or choose another file)" `
        -OtherFilePromptText "Enter the path to the PFX file to convert" `
        -EmptyArrayMessage "No PFX found in the working folders - use 'Select Another File'" `
        -SeparatorColor Blue
    if (-not $oSel -or ($oSel.PSTypeNames -and $oSel.PSTypeNames[0] -eq "DialogResult.Action.Back")) { return }
    $oFile = $oSel.Value
    if (-not $oFile) { return }

    $bExternal = ($oSel.PSTypeNames -and $oSel.PSTypeNames[0] -eq "DialogResult.Action.Other")
    if ($bExternal) {
        $sName = [System.IO.Path]::GetFileNameWithoutExtension($oFile.FullName)
        $sCertFolder = Join-Path $sWorkingDir ($sName + "_" + (Get-Date -Format "yyyyMMdd-HHmmss"))
        New-Item -Path $sCertFolder -ItemType Directory -Force | Out-Null
        $sPfxPath = Join-Path $sCertFolder $oFile.Name
        Copy-Item -LiteralPath $oFile.FullName -Destination $sPfxPath -Force
        Write-Host "Copied PFX to working folder: $sCertFolder" -ForegroundColor Cyan
    } else {
        $sPfxPath = $oFile.FullName
        $sCertFolder = $oFile.Directory.FullName
    }

    # 2. Read the source PFX password (validated by actually opening the PFX)
    $ssSrcPwd = $null
    while ($true) {
        $ssSrcPwd = Read-Host -AsSecureString -Prompt "Source PFX password (leave empty if none)"
        $sPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ssSrcPwd))
        try {
            $oTest = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                $sPfxPath, $sPlain, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            if ($oTest) { break }
        } catch {
            Write-Host "Cannot open the PFX with this password. Please try again." -ForegroundColor Red
        }
    }

    # 3. Conversion options form
    $oOpt = Read-PFXConversionOptions -AllowBack
    if ($null -eq $oOpt) { return }
    if ($oOpt.PSTypeNames -and $oOpt.PSTypeNames[0] -like "DialogResult.Action.*") { return }

    # 4. Normalize per container
    $sContainer = $oOpt.Container
    $bIsPem = ($sContainer -eq "PEMCombined" -or $sContainer -eq "PEMSeparate")
    $bIncludeKey = if ($sContainer -eq "DER") { $false } elseif ($sContainer -eq "PFX") { $true } else { $oOpt.IncludeKey }
    $bEncrypt = ($oOpt.Protection -eq "Encrypt")

    # 5. Output passwords (only when encryption is requested and meaningful)
    $ssOutKeyPwd = $null
    $ssOutPfxPwd = $null
    if ($sContainer -eq "PFX" -and $bEncrypt) {
        $ssOutPfxPwd = Read-CLIDialogNewPassword -Header "Output PFX password" -ErrorNotMatching "Passwords are not the same, please try again"
        if ($null -eq $ssOutPfxPwd) { return }
    } elseif ($bIsPem -and $bIncludeKey -and $bEncrypt) {
        $ssOutKeyPwd = Read-CLIDialogNewPassword -Header "Private key password" -ErrorNotMatching "Passwords are not the same, please try again"
        if ($null -eq $ssOutKeyPwd) { return }
    }

    # 6. Output folder + base name
    $sStamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $sBaseName = [System.IO.Path]::GetFileNameWithoutExtension($sPfxPath)
    $sOutDir = Join-Path $sCertFolder ("export_" + $sStamp)
    New-Item -Path $sOutDir -ItemType Directory | Out-Null

    # 7. Run the conversion engine
    $hConv = @{
        PfxPath     = $sPfxPath
        PfxPassword = $ssSrcPwd
        OutputDir   = $sOutDir
        BaseName    = $sBaseName
        Container   = $sContainer
        OpenSSLPath = $OpenSSLPath
    }
    if ($oOpt.IncludeChain) { $hConv.IncludeChain = $true }
    if ($oOpt.IncludeRoot)  { $hConv.IncludeRoot = $true }
    if ($bIncludeKey)       { $hConv.IncludeKey = $true }
    if ($bIsPem) {
        $hConv.KeyFormat = $oOpt.KeyFormat
        $hConv.KeyEncryption = if ($bEncrypt) { "Encrypt" } else { "Plain" }
        if ($ssOutKeyPwd) { $hConv.OutKeyPassword = $ssOutKeyPwd }
    }
    if ($sContainer -eq "PFX" -and $ssOutPfxPwd) { $hConv.OutPfxPassword = $ssOutPfxPwd }

    $oResult = try {
        Convert-CertificateFormat @hConv
    } catch {
        Write-Host "Conversion failed: $_" -ForegroundColor Red
        Remove-Item -LiteralPath $sOutDir -Recurse -Force -ErrorAction SilentlyContinue
        return
    }

    # 8. When a private key is in clear, wrap everything in a password-protected ZIP
    if ($oResult.KeyInClear) {
        Write-Host "The output holds an unencrypted private key; it will be stored in a password-protected ZIP." -ForegroundColor Yellow
        # 7-Zip's command line cannot carry a double-quote in the password, so reject it here.
        $ssZipPwd = $null
        while ($true) {
            $ssZipPwd = Read-CLIDialogNewPassword -Header "ZIP password (the double-quote character is not supported)" -ErrorNotMatching "Passwords are not the same, please try again"
            if ($null -eq $ssZipPwd) {
                Write-Host "No ZIP password provided. Aborting and cleaning up." -ForegroundColor Red
                foreach ($f in $oResult.Files) { Remove-FileSecure -Path $f }
                Remove-Item -LiteralPath $sOutDir -Recurse -Force -ErrorAction SilentlyContinue
                return
            }
            $sZipChk = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ssZipPwd))
            if ($sZipChk.Contains('"')) {
                Write-Host "The ZIP password cannot contain a double-quote (`") character; 7-Zip cannot carry it. Please choose another." -ForegroundColor Yellow
                continue
            }
            break
        }
        $sAnswer = Invoke-YesNoCLIDialog -YN -Vertical -Message "ZIP encryption method?" `
            -YesButtonText "AES-256 (security - needs 7-Zip / WinZip to open)" `
            -NoButtonText "ZipCrypto (compatibility - opens in Windows Explorer, weaker)"
        $sMethod = if ($sAnswer -eq "Yes") { "AES256" } else { "ZipCrypto" }

        $sZip = Join-Path $sCertFolder ("export_" + $sStamp + ".zip")
        try {
            New-7ZipArchive -Content $oResult.Files -OutputArchivePath $sZip -ArchiveType zip -Password $ssZipPwd -ZipEncryptionMethod $sMethod
        } catch {
            Write-Host "ZIP creation failed: $_" -ForegroundColor Red
            return
        }
        # Remove the plaintext output so only the encrypted ZIP remains in the target folder
        foreach ($f in $oResult.Files) { Remove-FileSecure -Path $f }
        Remove-Item -LiteralPath $sOutDir -Recurse -Force -ErrorAction SilentlyContinue

        if (Test-Path -LiteralPath $sZip) {
            Write-Host "Password-protected ZIP created ($sMethod):" -ForegroundColor Green
            Write-Host "  $sZip"
        } else {
            Write-Host "ZIP creation failed." -ForegroundColor Red
        }
    } else {
        Write-Host "Conversion done. Files created in:" -ForegroundColor Green
        Write-Host "  $sOutDir"
        foreach ($f in $oResult.Files) { Write-Host ("    " + (Split-Path $f -Leaf)) }
    }
    Write-Host ""
}

function Invoke-SignCSR_CLI {
    # Sign a CSR provided as input: the CSR file path is entered directly (it usually comes
    # from someone else), the CSR is displayed first (the signer may refuse), the signer
    # chooses the CA and the template (the requester rarely provides one), and the signed
    # certificate + chain are written to a new working folder named after the subject CN.
    # No PFX is produced: the private key belongs to the requester, not to the signer.

    # 1. Enter the CSR file path
    $oPath = Read-CLIDialogFilePath -Header "Enter the path to the CSR file to sign" `
        -PropertyName "CSR path" -AllowBack -ErrorMessage "File not found"
    if ($null -eq $oPath) { return }
    if ($oPath.PSTypeNames -and $oPath.PSTypeNames[0] -like "DialogResult.Action.*") { return }
    $sCSRPath = if ($oPath -is [System.IO.FileInfo]) { $oPath.FullName } else { ([string]$oPath).Trim().Trim('"').Trim("'") }

    # 2. Parse and display the CSR before signing
    $oCSRInfo = try {
        Get-CSRInfo -Path $sCSRPath
    } catch {
        Write-Host "Unable to read the CSR: $_" -ForegroundColor Red
        Write-Host ""
        return
    }
    Write-Host ""
    Write-Host "-------------------------- CSR to sign --------------------------" -ForegroundColor Blue
    Write-CSRInfoToHost -CSRInfo $oCSRInfo
    Write-Host ("Public key`t: {0} {1} bits" -f $oCSRInfo.PublicKeyAlgorithm, $oCSRInfo.PublicKeySize)
    Write-Host ("Hash`t`t: {0}" -f $oCSRInfo.HashAlgorithm)
    Write-Host "-----------------------------------------------------------------" -ForegroundColor Blue
    Write-Host ""

    # 3. Confirm intent (the signer may decline)
    $sConfirm = Invoke-YesNoCLIDialog -YN -Vertical -Message "Do you want to sign this CSR?" `
        -YesButtonText "&Yes, sign it" -NoButtonText "&No, do not sign"
    if ($sConfirm -ne "Yes") { return }

    # 4. Choose the CA
    $oCA = if ($ScriptConfig.CAFilter -and ($ScriptConfig.CAFilter -ne "")) { Read-CA $ScriptConfig.CAFilter } else { Read-CA }
    if ($null -ne $oCA -and $oCA.PSObject.TypeNames[0] -eq "DialogResult.Action.Back") { return }
    if (-not (($null -ne $oCA) -and ($oCA.PSObject.TypeNames[0] -eq "ADcertificationAuthority"))) {
        Write-Host "No certificate authority selected. Aborting." -ForegroundColor Yellow
        Write-Host ""
        return
    }
    $sCAName = $oCA.Name

    # 5. Choose the template (default to the one in the CSR, if any)
    $oTemplate = if ($ScriptConfig.TemplateFilter -and ($ScriptConfig.TemplateFilter -ne "")) {
        Read-TemplateName -CA $sCAName -TemplateFilter $ScriptConfig.TemplateFilter -DefaultTemplateName $oCSRInfo.TemplateName
    } else {
        Read-TemplateName -CA $sCAName -DefaultTemplateName $oCSRInfo.TemplateName
    }
    if ($null -ne $oTemplate -and $oTemplate.PSObject.TypeNames[0] -eq "DialogResult.Action.Back") { return }
    $sTemplateName = if (($oTemplate -is [hashtable]) -and $oTemplate.CertificateTemplate) { $oTemplate.CertificateTemplate } else { "" }

    # 6. Resolve the PKI server hosting the CA and connect
    $sPKIServer = (Get-CAEnrollmentServices -NameFilter ("^" + $sCAName + "$")).DNSHostName
    if (-not $sPKIServer) {
        Write-Host "Could not resolve the PKI server for CA '$sCAName'." -ForegroundColor Red
        Write-Host ""
        return
    }
    if (-not (Connect-PKIServer -PKIServer $sPKIServer)) {
        Write-Error "Can't connect to PKI server"
        return
    }

    # 7. Submit the CSR (with the chosen template)
    $hSubmit = @{
        CSRContent = (Get-Content -Path $sCSRPath -Raw)
        CAName     = $sCAName
        Session    = $Global:PKISession
    }
    if ($sTemplateName) { $hSubmit.TemplateName = $sTemplateName }
    Write-Host "------------------------- Send-CSRToCA --------------------------" -ForegroundColor Blue
    $oSubmit = Send-CSRToCA @hSubmit
    if (-not $oSubmit.Success) {
        Write-Host "CSR submission failed (disposition $($oSubmit.Disposition))." -ForegroundColor Red
        Write-Host ""
        return
    }
    Write-Host "CSR submitted. RequestID: $($oSubmit.RequestID)"
    $iRequestID = $oSubmit.RequestID

    # 8. If pending approval, issue it now (signer acts as approver)
    if ($oSubmit.Disposition -eq 5) {
        Write-Host "Request is pending approval; issuing it now..." -ForegroundColor Yellow
        $oSign = Sign-CSR -Session $Global:PKISession -RequestID $iRequestID -CAName $sCAName
        if (-not $oSign.Success) {
            Write-Host "Failed to issue the pending request." -ForegroundColor Red
            Write-Host ($oSign.Output -join "`n")
            Write-Host ""
            return
        }
    }

    # 9. Retrieve the signed certificate + chain into a new working folder named after the CN
    $sCN = if ($oCSRInfo.Subject -match "CN=([^,]+)") { $matches[1] } else { "signed-csr" }
    $sSafeName = ConvertTo-SafeFileName -Name $sCN
    $sOutFolder = Join-Path (Get-ScriptDir -WorkingDir) $sSafeName
    if (Test-Path $sOutFolder) {
        $sOutFolder = $sOutFolder + "_" + (Get-Date -Format "yyyyMMdd-HHmmss")
    }
    New-Item -Path $sOutFolder -ItemType Directory -Force | Out-Null
    $sOutCer = Join-Path $sOutFolder ($sSafeName + ".cer")
    $sOutP7b = Join-Path $sOutFolder ($sSafeName + ".p7b")

    Write-Host "--------------------- Get-IssuedCertificate ---------------------" -ForegroundColor Blue
    $oRetrieve = Get-IssuedCertificate -Session $Global:PKISession -RequestID $iRequestID -CAName $sCAName -CertOut $sOutCer -CertChainOut $sOutP7b
    if ($oRetrieve.Success) {
        Write-Host "Certificate signed successfully:" -ForegroundColor Green
        Write-Host "  $($oRetrieve.Cert)"
        Write-Host "  $($oRetrieve.CertChain)"
    } else {
        Write-Host "Failed to retrieve the signed certificate." -ForegroundColor Red
    }
    Write-Host ""
}

$OpenSSLPath = Get-OpenSSLLocation

if (-not (Test-Path -Path $OpenSSLPath -PathType Leaf)) {
    throw "OpenSSL not found"
}

$ScriptConfig = Get-ThisScriptConfig

$mExit = New-MenuAction -Text "&Exit" -Exit
$mBack = New-MenuAction -Text "&Back" -Back

$aOtherMenuItems = @(
    $mBack
    $mExit
)

$Menu = New-Menu -Text "What do you want to do?" -Content @(
    New-Menu -Text "&Create CSR, Sign with PKI and create PFX" -Content @(
        New-MenuItem -Text "Ask for &items (recommended)" -Content { New-PKISignedCertAndPFX_CLI -OpenSSLPath $OpenSSLPath -ItemsMode | Out-Null } -Recommended
        New-MenuItem -Text "Full Object &DN" -Content { New-PKISignedCertAndPFX_CLI -OpenSSLPath $OpenSSLPath | Out-Null }
        New-MenuItem -Text "I&mport from existing certificate" -Content { Invoke-ImportCertFlow_CLI -OpenSSLPath $OpenSSLPath | Out-Null }
    ) -OtherMenuItems $aOtherMenuItems -SeparatorColor Blue
    New-MenuItem -Text "Sig&n a provided CSR" -Content { Invoke-SignCSR_CLI | Out-Null }
    New-Menu -Text "&Advanced certificate generation" -Content @(
        New-Menu -Text "&New Certificate Request" -Content @(
            New-MenuItem -Text "Specify items (recommended)" -Recommended -Content { New-CSR_CLI -OpenSSLPath $OpenSSLPath -ItemsMode | Out-Null }
            New-MenuItem -Text "Specify DN" -Content { New-CSR_CLI -OpenSSLPath $OpenSSLPath | Out-Null }
            New-MenuItem -Text "I&mport from existing certificate" -Content { Invoke-ImportCSRFlow_CLI -OpenSSLPath $OpenSSLPath | Out-Null }
        ) -OtherMenuItems $aOtherMenuItems -SeparatorColor Blue
        New-MenuItem -Text "&Send CSR to CA" -Content { Send-CSRToCA_CLI | Out-Null }
        New-MenuItem -Text "&Issue pending certificate request" -Content { Invoke-IssueCSR_CLI | Out-Null }
        New-MenuItem -Text "&Get issued certificate" -Content { Get-IssuedCertificate_CLI | Out-Null }
        New-MenuItem -Text "&Create PFX" -Content { New-PFX_CLI -OpenSSLPath $OpenSSLPath }    
    ) -OtherMenuItems $aOtherMenuItems -SeparatorColor Blue
    New-MenuItem -Text "E&xport / Convert certificate" -Content { Convert-Certificate_CLI -OpenSSLPath $OpenSSLPath | Out-Null }
    New-MenuItem -Text "&Settings" -Content { Edit-ScriptConfig }
) -OtherMenuItems $mExit -SeparatorColor Blue

Invoke-Menu -Menu $Menu
