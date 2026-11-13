Param(
    [string]$InputDir,
    [string]$WorkingDir
)

$iModulesCount = 11
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
Write-Progress -Activity "Loading script modules" -Status "PSSomeMSSqlThings" -PercentComplete (($($i++; $i) / $iModulesCount) * 100)
Import-Module $PSScriptRoot\UDF\PSSomeMSSqlThings -Force
Write-Progress -Activity "Loading script modules" -Status "PSSomeNetworkThings" -PercentComplete (($($i++; $i) / $iModulesCount) * 100)
Import-Module $PSScriptRoot\UDF\PSSomeNetworkThings -Force
Write-Progress -Activity "Loading script modules" -Status "PSSomeNetScalerThings" -PercentComplete (($($i++; $i) / $iModulesCount) * 100)
Import-Module $PSScriptRoot\UDF\PSSomeNetScalerThings -Force
Write-Progress -Activity "Loading script modules" -Status "PSSomeRDSThings" -PercentComplete (($($i++; $i) / $iModulesCount) * 100)
Import-Module $PSScriptRoot\UDF\PSSomeRDSThings -Force
Write-Progress -Activity "Loading script modules" -Status "Loading end" -PercentComplete 100 -Completed
#endregion Include

#region script info
#scriptVersion=2.9
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

2.6 (2026-10-25):
- Added "Change the certificate of an RDS server": connects to the server, shows the
  certificates currently in use, then deploys a PFX (from a working folder or any path).
  The deployment mode is auto-detected: on a Connection Broker the roles to update are
  chosen (RD Gateway, RD Web Access, RD Publishing, RD Redirector); on a standalone
  Session Host the certificate is bound to the RDP-tcp listener.
  The certificate to deploy can be:
    - renewed with the same parameters: subject and SAN of the current certificate, CA and
      template reused from the last request made for that CN (asked when none is found),
      only the private key password is asked,
    - a new certificate generated with the PKI (form pre-filled from the current certificate),
    - an existing PFX (working folder or any path).
  A PFX generated this way is deployed directly (no password prompt again).

2.7 (2026-11-06):
- Added "View a certificate": choose a working folder then one of its certificate files (a
  folder holding a single file opens it directly), or "Other source" to enter a file path,
  an HTTPS URL, a host[:port] (port 443 by default; HTTPS and SQL Server are tried at the same
  time, the first answer wins) or a
  SQL Server instance ("server\instance", port asked to the SQL Server Browser, or "server,port").
  For a server, the certificate it presents to its clients is shown (no login needed).
  Every list has Back and Exit. PEM (bundles included), DER, P7B and PFX/P12
  (password asked when needed) are supported; when the source holds several certificates,
  the one to view is chosen in a list ordered from the leaf to the root.
  Displayed: subject, SAN, issuer, serial, validity (days left), SHA1/SHA256 fingerprints,
  public key, signature algorithm, key usages, basic constraints, template, SKI/AKI,
  CDP/AIA/OCSP URLs, private key presence, and the chain check on this computer.
  The SAN are listed one per line, grouped by type. From the displayed certificate you can
  create a new certificate or only a CSR (subject and SAN pre-filled), copy the DNS / IP SAN
  to the clipboard (one per line, as the request form expects them), open it in the Windows
  certificate viewer or decode it fully with OpenSSL.
- "Import from existing certificate" now also accepts a PFX (password asked), a P7B or a
  PEM bundle (the leaf certificate is used).
- "Change the certificate of an RDS server" moved to a "Change the certificate of an application
  server" sub-menu, which also holds:
- Added "SQL Server": renews the TLS certificate of a SQL Server instance. The instances of the
  server are detected (configured certificate, certificate presented on the network, restart
  pending), the certificate comes from the same choices as for RDS (renewal, new request,
  existing PFX), then it is prepared without interruption: import in LocalMachine\My, read access
  to the private key for the service account, thumbprint in the instance configuration. The
  instance is restarted now or later, as chosen (SQL Server reads its certificate at startup),
  and the certificate presented after the restart is checked. Encryption settings
  (ForceEncryption...) are never changed. Server side work in the new PSSomeMSSqlThings module.
- Fixed: a host:port ("server.lan:443") was refused when importing or viewing a certificate,
  and the certificate name was not extracted from a "<name>_<date>" working folder (the whole
  folder name was used for the files) - both came from the DNS regex of PSSomeDataThings.

2.8 (2026-11-12):
- Added an expiring-certificate report with template inclusion/exclusion filters, bounded
    history lookup based on template validity, renewal deduplication by CN/SAN, a prefilled
    PKI request workflow, and Excel-friendly CSV export.
- Added NetScaler ADC certificate discovery through a dedicated read-only Nitro module,
    available under the application server certificate menu.

2.9 (2026-11-13):
- Added a parameter form before running the expiring-certificate report: days ahead and
    template inclusion/exclusion filters are prefilled from the saved configuration and can
    be changed for that execution without saving them. Invalid values retain the entered data.
- Added online CRL/OCSP revocation checks to the report: confirmed revoked certificates are
    excluded, while inconclusive checks remain visible as Unknown. The list shows the status,
    and CSV exports include both the revocation status and details.
- Selecting an expiring certificate now displays its details and CA request metadata before
    offering renewal, CSR-only generation, Windows viewer and OpenSSL actions. The report is
    loaded once; returning from the details or exporting CSV does not query the PKI again.
- Simplified the report table to CN, SAN, expiry date, days remaining, revocation status and
    template. CN and SAN remain separate columns, with AutoWidth truncation applied to SAN.
    Display column selection preserves all record properties for the details and CSV export.
- Improved table sizing in narrow consoles: dates use the local short date format when needed,
    column widths are recalculated, and rightmost columns are hidden if their headers cannot fit.
    AutoWidth no longer receives a negative width, and dates and numbers are truncated correctly.
    These display changes do not modify source objects or exported report data.
- Fixed the missing RevocationDetails property that prevented report generation.
- Fixed Exit in the expiring-certificate report: the action object is returned to the main menu,
    which remains responsible for exiting the application.

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
        [switch]$AllowBack,
        [string]$FriendlyName   # when set, no dialog: this name is used directly
    )
    $sFriendlyName = if ($FriendlyName) {
        $FriendlyName
    } else {
        $oFriendlyName = Read-CLIDialogFilePath `
            -Header "Please enter a friendly name. It will be used to generate certificate files and used in the pfx." `
            -PropertyName "Friendly name" -AllowNonExisting -AllowBack:$AllowBack `
            -DefaultValue $DefaultFriendlyName -ErrorMessage "Friendly name cannot be empty"
        if ($null -ne $oFriendlyName -and $oFriendlyName.PSTypeNames -and $oFriendlyName.PSTypeNames[0] -eq "DialogResult.Action.Back") {
            return $oFriendlyName
        }
        $oFriendlyName
    }
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
        -Header "Enter a certificate file path, an HTTPS URL, a host[:port] (HTTPS, else SQL Server) or a SQL Server instance (server\instance) to import" `
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
    $oCert = $null
    try {
        # A file can hold several certificates (P7B, PEM bundle): keep the leaf
        $oCert = Get-SortedCertificateChain -Certificates @(Get-CertificateFromInput -InputString $sInput) | Select-Object -First 1
    } catch {
        Write-Host "Failed to load certificate: $_" -ForegroundColor Red
        return $null
    }
    if (-not $oCert) { return $null }

    Write-Host "Imported certificate subject: $($oCert.Subject)" -ForegroundColor Green

    return ConvertTo-CertFormValues -Certificate $oCert
}

function ConvertTo-CertFormValues {
    # Builds the wizard initial values (certificate object + SAN) from an existing certificate
    Param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $oCert = $Certificate
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
        [hashtable]$InitialValues,
        [hashtable]$PrebuiltCSR   # @{ CSR; MoreInfo } already built (same shape as Read-CSR): no wizard
    )
    $oCSR = if ($PrebuiltCSR) { $PrebuiltCSR } else { Read-CSR -ItemsMode:$ItemsMode -InitialValues $InitialValues }
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
    $sRegex = "^(?<dns>$(Get-DNSRegex -NoBoundary))_[0-9]{4,4}(0[1-9]|1[0-2])(0[1-9]|1[0-9]|2[0-9]|30|31)-((0|1)[0-9]|2[0-3])[0-5][0-9][0-5][0-9]$"
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
        [string]$CertFolder,
        [switch]$ForWindowsStore
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
    $sWindowsPFX = if ($ForWindowsStore) {
        "Yes"
    } else {
        Invoke-YesNoCLIDialog -YN -Message "Will this PFX be used in the Windows certificate store?"
    }

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
        return [pscustomobject]@{
            PfxPath  = $sOutPFXFile
            Password = $ssKeyPassword
            Folder   = $sCertFolder
        }
    } else {
        Write-Host "PFX generation failed" -ForegroundColor Red
        Write-Host ""
    }
}

function New-PKISignedCertAndPFX_CLI {
    Param(
        [string]$OpenSSLPath,
        [switch]$ItemsMode,
        [hashtable]$InitialValues,
        [hashtable]$PrebuiltCSR,
        [switch]$ForWindowsStore
    )
    # Returns the New-PFX_CLI result (PfxPath, Password, Folder) on success, nothing on failure
    $oCSR = New-CSR_CLI -OpenSSLPath $OpenSSLPath -ItemsMode:$ItemsMode -InitialValues $InitialValues -PrebuiltCSR $PrebuiltCSR
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
                $oPfx = New-PFX_CLI -OpenSSLPath $OpenSSLPath -PrivateKeyPassword $oCSR.CSR.KeyPassword -CertFolder $oCSR.Folder -ForWindowsStore:$ForWindowsStore
                Write-Host "-----------------------------------------------------------------" -ForegroundColor Blue
                return $oPfx
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
        $oConfig = Get-Content -Path $sPath | ConvertFrom-Json
    } else {
        $oConfig = [PSCustomObject]@{}
    }
    $hDefaults = @{
        CAFilter = ""
        TemplateFilter = ""
        ReportTemplateFilter = ""
        ReportTemplateExcludeFilter = ""
        ReportDaysAhead = 30
    }
    foreach ($sProperty in $hDefaults.Keys) {
        if (-not $oConfig.PSObject.Properties[$sProperty]) {
            $oConfig | Add-Member -NotePropertyName $sProperty -NotePropertyValue $hDefaults[$sProperty]
        }
    }
    return $oConfig
}

function Edit-ScriptConfig {
    $hProperties = [ordered]@{
        "CAFilter" = @{ Text = $ScriptConfig.CAFilter }
        "TemplateFilter" = @{ Text = $ScriptConfig.TemplateFilter }
        "ReportTemplateFilter" = @{ Text = $ScriptConfig.ReportTemplateFilter }
        "ReportTemplateExcludeFilter" = @{ Text = $ScriptConfig.ReportTemplateExcludeFilter }
        "ReportDaysAhead" = @{ Text = [string]$ScriptConfig.ReportDaysAhead }
    }
    $oResult = Read-CLIDialogHashtable -Properties $hProperties -Header "Script configuration" -AllowCancel
    if ($null -ne $oResult) {
        $iReportDaysAhead = 0
        if (-not [int]::TryParse([string]$oResult.ReportDaysAhead, [ref]$iReportDaysAhead) -or $iReportDaysAhead -lt 1) {
            Write-Host "ReportDaysAhead must be a positive number." -ForegroundColor Red
            return
        }
        foreach ($sFilter in @($oResult.ReportTemplateFilter, $oResult.ReportTemplateExcludeFilter) | Where-Object { $_ }) {
            try { $null = [regex]::new([string]$sFilter) } catch {
                Write-Host "Invalid report template regular expression: $sFilter" -ForegroundColor Red
                return
            }
        }
        $ScriptConfig.CAFilter = $oResult.CAFilter
        $ScriptConfig.TemplateFilter = $oResult.TemplateFilter
        $ScriptConfig.ReportTemplateFilter = $oResult.ReportTemplateFilter
        $ScriptConfig.ReportTemplateExcludeFilter = $oResult.ReportTemplateExcludeFilter
        $ScriptConfig.ReportDaysAhead = $iReportDaysAhead
        $ScriptConfig | ConvertTo-Json -Depth 10 | Out-File (Get-ThisScriptConfigPath) -Encoding utf8
        Write-Host "Configuration saved." -ForegroundColor Green
        Write-Host ""
    }
}

function Show-NetScalerCertificateCheck_CLI {
    $oInput = Read-CLIDialogValidatedValue -Header "NetScaler management URL (HTTPS)" `
        -PropertyName "URL" -ValidationMethod { param($v) return ($v.Trim().Length -gt 0) } `
        -ErrorMessage "URL cannot be empty" -AllowCancel
    if ($null -eq $oInput -or ($oInput.PSTypeNames -and $oInput.PSTypeNames[0] -like "DialogResult.Action.*")) { return }
    $sManagementInput = if ($oInput.PSTypeNames -and $oInput.PSTypeNames[0] -eq "DialogResult.Value") { [string]$oInput.Value } else { [string]$oInput }
    $sManagementInput = $sManagementInput.Trim().TrimEnd('/')
    if ($sManagementInput -notmatch '^https://') { $sManagementInput = "https://$sManagementInput" }

    $oCredential = Read-CLIDialogCredential -Credential $Global:NetScalerCredential `
        -Message "NetScaler Nitro API credentials" -AddCancel
    if ($null -eq $oCredential) { return }
    $Global:NetScalerCredential = $oCredential

    $oNitroSession = $null
    try {
        $oNitroSession = Connect-NetScalerNitroSession -ManagementUri $sManagementInput -Credential $oCredential
        $aEndpoints = @(Get-NetScalerSSLEndpoint -Session $oNitroSession)
    } catch {
        Write-Warning "Could not discover SSL virtual servers from NetScaler: $_"
        return
    } finally {
        if ($oNitroSession) { Disconnect-NetScalerNitroSession -Session $oNitroSession }
    }
    if ($aEndpoints.Count -eq 0) {
        Write-Host "No SSL/SSL_TCP virtual servers were discovered." -ForegroundColor Yellow
        return
    }

    $hCertificatesByThumbprint = @{}
    $aChecks = @()
    foreach ($oEndpoint in $aEndpoints) {
        $oCertificate = $null
        $oCertificateInfo = $null
        $sStatus = 'Unavailable'
        try {
            $oEndpointUri = New-Object System.UriBuilder('https', [string]$oEndpoint.HostName, [int]$oEndpoint.Port)
            $oCertificate = Get-CertificateFromUrl -Url $oEndpointUri.Uri.AbsoluteUri -TimeoutSeconds 10
            if ($oCertificate -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                throw "TLS probe returned '$($oCertificate.GetType().FullName)' instead of X509Certificate2."
            }

            $sThumbprint = ([string]$oCertificate.Thumbprint).Trim().ToUpperInvariant()
            if ($sThumbprint -and $hCertificatesByThumbprint.ContainsKey($sThumbprint)) {
                $oCertificate.Dispose()
                $oCertificateInfo = $hCertificatesByThumbprint[$sThumbprint]
            } else {
                $aSANEntries = @(Get-CertificateSAN -Certificate $oCertificate -AsList)
                $sSAN = if ($aSANEntries.Count -gt 0) {
                    (@($aSANEntries | ForEach-Object { "{0}: {1}" -f $_.Type, $_.Value }) -join '; ')
                } else { '-' }
                $oTemplate = Get-CertificateTemplate -Certificate $oCertificate
                $oCertificateInfo = [PSCustomObject]@{
                    Certificate = $oCertificate
                    Subject = $oCertificate.Subject
                    Issuer = $oCertificate.Issuer
                    Thumbprint = $oCertificate.Thumbprint
                    SerialNumber = $oCertificate.SerialNumber
                    NotBefore = $oCertificate.NotBefore
                    NotAfter = $oCertificate.NotAfter
                    CertificateTemplate = if ($oTemplate.Name) { $oTemplate.Name } elseif ($oTemplate.OID) { $oTemplate.OID } else { '-' }
                    SAN = $sSAN
                }
                if ($sThumbprint) { $hCertificatesByThumbprint[$sThumbprint] = $oCertificateInfo }
            }
            $sStatus = if ($oCertificateInfo.NotAfter -le (Get-Date)) { 'Expired' } else { 'Presented' }
        } catch {
            Write-Verbose "TLS probe failed for $($oEndpoint.HostName):$($oEndpoint.Port): $_"
            if ($oCertificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2] -and
                -not ($hCertificatesByThumbprint.Values.Certificate -contains $oCertificate)) {
                $oCertificate.Dispose()
            }
        }

        $aChecks += [PSCustomObject]@{
            HostName = $oEndpoint.HostName
            Port = $oEndpoint.Port
            VirtualServer = $oEndpoint.VirtualServer
            Type = $oEndpoint.VirtualServerType
            Source = $oEndpoint.DiscoverySource
            Status = $sStatus
            CertificateSubject = if ($oCertificateInfo) { $oCertificateInfo.Subject } else { '-' }
            Issuer = if ($oCertificateInfo) { $oCertificateInfo.Issuer } else { '-' }
            Thumbprint = if ($oCertificateInfo) { $oCertificateInfo.Thumbprint } else { '-' }
            SerialNumber = if ($oCertificateInfo) { $oCertificateInfo.SerialNumber } else { '-' }
            SAN = if ($oCertificateInfo) { $oCertificateInfo.SAN } else { '-' }
            CertificateTemplate = if ($oCertificateInfo) { $oCertificateInfo.CertificateTemplate } else { '-' }
            NotBefore = if ($oCertificateInfo) { $oCertificateInfo.NotBefore } else { $null }
            NotAfter = if ($oCertificateInfo) { $oCertificateInfo.NotAfter } else { $null }
        }
    }

    try {
        while ($true) {
            $oSelection = Select-CLIDialogObjectInArray -Objects $aChecks `
                -SelectedColumns @('HostName', 'Port', 'VirtualServer', 'Type', 'Status', @{ n = 'SAN'; e = { $_.SAN }; AutoWidth = $true }, 'CertificateTemplate', 'NotAfter') `
                -SelectHeaderMessage 'NetScaler HTTPS certificates discovered from the ADC' `
                -OtherMenuItems @(
                    New-CLIDialogButton -Text '&Generate CSV report' -Other -Object { 'ExportReport' }
                    New-CLIDialogButton -Text '&Exit' -Exit
                ) -ItemsPerPage 10 -Space:$false -AllowBack

            if ($oSelection.PSTypeNames -and $oSelection.PSTypeNames[0] -eq 'DialogResult.Action.Other') {
                if ($oSelection.Value -eq 'ExportReport') {
                    $sOutputDir = Get-ScriptDir -OutputDir
                    New-Item -Path $sOutputDir -ItemType Directory -Force | Out-Null
                    $sReportPath = Join-Path $sOutputDir ("NetScalerCertificates_{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
                    $aChecks | Select-Object HostName, Port, VirtualServer, Type, Source, Status, CertificateSubject, Issuer, Thumbprint, SerialNumber, SAN, CertificateTemplate, NotBefore, NotAfter |
                        Export-Csv -Path $sReportPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
                    Write-Host "Report saved to: $sReportPath" -ForegroundColor Cyan
                }
                continue
            }
            if ($oSelection.PSTypeNames -and $oSelection.PSTypeNames[0] -eq 'DialogResult.Value') {
                if ($oSelection.Value.Thumbprint -eq '-') {
                    Write-Warning "No certificate was obtained from $($oSelection.Value.HostName):$($oSelection.Value.Port)."
                    continue
                }
                $oEndpointUri = New-Object System.UriBuilder('https', [string]$oSelection.Value.HostName, [int]$oSelection.Value.Port)
                $oViewResult = Show-CertificateSource_CLI -Source $oEndpointUri.Uri.AbsoluteUri -OpenSSLPath $OpenSSLPath
                if (Test-DialogAction $oViewResult -Action 'Exit') { return $oViewResult }
                continue
            }
            return
        }
    } finally {
        foreach ($oInfo in $hCertificatesByThumbprint.Values) {
            if ($oInfo.Certificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) { $oInfo.Certificate.Dispose() }
        }
    }
}

function Show-ExpiringCertificates_CLI {
    $iDaysAhead = 30
    if (-not [int]::TryParse([string]$ScriptConfig.ReportDaysAhead, [ref]$iDaysAhead) -or $iDaysAhead -lt 1) { $iDaysAhead = 30 }
    $hReportProperties = [ordered]@{
        ReportDaysAhead = @{ Text = [string]$iDaysAhead; Regex = '^[0-9]+$' }
        ReportTemplateFilter = @{ Text = [string]$ScriptConfig.ReportTemplateFilter }
        ReportTemplateExcludeFilter = @{ Text = [string]$ScriptConfig.ReportTemplateExcludeFilter }
    }
    while ($true) {
        $oReportParameters = Read-CLIDialogHashtable -Properties $hReportProperties `
            -Header "Expiring certificate report parameters" -AllowCancel
        if ($null -eq $oReportParameters) { return }
        foreach ($sProperty in $hReportProperties.Keys) {
            $hReportProperties[$sProperty].Text = [string]$oReportParameters[$sProperty]
        }

        if (-not [int]::TryParse([string]$oReportParameters.ReportDaysAhead, [ref]$iDaysAhead) -or
            $iDaysAhead -lt 1 -or $iDaysAhead -gt 36500) {
            Write-Host "ReportDaysAhead must be between 1 and 36500." -ForegroundColor Red
            continue
        }
        $sTemplateFilter = [string]$oReportParameters.ReportTemplateFilter
        $sTemplateExcludeFilter = [string]$oReportParameters.ReportTemplateExcludeFilter
        $bValidFilters = $true
        foreach ($sFilter in @($sTemplateFilter, $sTemplateExcludeFilter) | Where-Object { $_ }) {
            try { $null = [regex]::new($sFilter) } catch {
                Write-Host "Invalid report template regular expression: $sFilter" -ForegroundColor Red
                $bValidFilters = $false
            }
        }
        if ($bValidFilters) { break }
    }

    $oCredential = $Global:PKICredential
    if ($null -eq $oCredential) {
        $oCredential = Read-CLIDialogCredential -Message "Enter credentials to query the PKI" -AddCancel
        if ($null -eq $oCredential) { return }
        $Global:PKICredential = $oCredential
    }

    try {
        $aExpiringCertificates = @(Get-ExpiringCAIssuedCertificates -Credential $oCredential `
            -DaysAhead $iDaysAhead -TemplateFilter $sTemplateFilter `
            -ExcludedTemplateFilter $sTemplateExcludeFilter -IncludeCertificate -CheckRevocation)
    } catch {
        Write-Warning "Could not list expiring certificates: $_"
        return
    }
    if ($aExpiringCertificates.Count -eq 0) {
        Write-Host "No certificates expire within the next $iDaysAhead day(s) after filtering and renewal deduplication." -ForegroundColor Green
        return
    }

    $aRows = @($aExpiringCertificates | ForEach-Object {
        $aSANParts = @()
        if ($_.SAN) {
            foreach ($sType in $_.SAN.Keys) {
                $aValues = @($_.SAN[$sType] | Where-Object { $null -ne $_ -and [string]$_ -ne '' })
                if ($aValues.Count -gt 0) { $aSANParts += "${sType}: $($aValues -join ', ')" }
            }
        }
        [PSCustomObject]@{
            CAName = $_.CAName
            RequestID = $_.RequestID
            SubmittedWhen = $_.SubmittedWhen
            ResolvedWhen = $_.ResolvedWhen
            CommonName = $_.CommonName
            SAN = if ($aSANParts.Count) { $aSANParts -join '; ' } else { '-' }
            CertificateTemplate = $_.CertificateTemplate
            IssuedOn = $_.IssuedOn
            NotAfter = $_.NotAfter
            DaysRemaining = $_.DaysRemaining
            RevocationStatus = $_.RevocationStatus
            RevocationDetails = $_.RevocationDetails
            RequesterName = $_.RequesterName
            SerialNumber = $_.SerialNumber
            CertificateHash = $_.CertificateHash
            Certificate = $_.Certificate
        }
    })

    while ($true) {
        $oSelection = Select-CLIDialogObjectInArray -Objects $aRows `
            -SelectedColumns @(
                @{ n = 'CN'; e = { $_.CommonName } }
                @{ n = 'SAN'; e = { $_.SAN }; AutoWidth = $true }
                @{ n = 'Expires'; e = { $_.NotAfter } }
                @{ n = 'Days'; e = { $_.DaysRemaining } }
                @{ n = 'Status'; e = { $_.RevocationStatus } }
                @{ n = 'Template'; e = { $_.CertificateTemplate } }
            ) `
            -SelectHeaderMessage 'Certificates expiring soon: select one to view its details' `
            -OtherMenuItems @(
                New-CLIDialogButton -Text '&Generate CSV report' -Other -Object { 'ExportReport' }
                New-CLIDialogButton -Text '&Exit' -Exit
            ) -ItemsPerPage 10 -Space:$false -AllowBack -HeaderTextInSeparator

        if (Test-DialogAction $oSelection -Action 'Exit') { return $oSelection }
        if ($oSelection.PSTypeNames -and $oSelection.PSTypeNames[0] -eq 'DialogResult.Action.Other') {
            if ($oSelection.Value -eq 'ExportReport') {
                $sOutputDir = Get-ScriptDir -OutputDir
                New-Item -Path $sOutputDir -ItemType Directory -Force | Out-Null
                $sReportPath = Join-Path $sOutputDir ("ExpiringCertificates_{0}.csv" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
                $aRows | Select-Object CAName, CommonName, SAN, CertificateTemplate, IssuedOn, NotAfter, DaysRemaining, RevocationStatus, RevocationDetails, RequesterName, SerialNumber, RequestID, SubmittedWhen, ResolvedWhen, CertificateHash |
                    Export-Csv -Path $sReportPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
                Write-Host "Report saved to: $sReportPath" -ForegroundColor Cyan
            }
            continue
        }

        if ($oSelection.PSTypeNames -and $oSelection.PSTypeNames[0] -eq 'DialogResult.Value') {
            $oDetailResult = Show-ExpiringCertificateDetails_CLI -CertificateRecord $oSelection.Value -OpenSSLPath $OpenSSLPath
            if (Test-DialogAction $oDetailResult -Action 'Exit') { return $oDetailResult }
            continue
        }
        return
    }
}

function Show-ExpiringCertificateDetails_CLI {
    Param(
        [Parameter(Mandatory)]
        [object]$CertificateRecord,
        [string]$OpenSSLPath
    )
    $oCertificate = $CertificateRecord.Certificate
    $bHasCertificate = $oCertificate -is [System.Security.Cryptography.X509Certificates.X509Certificate2]
    if ($bHasCertificate) {
        Write-CertificateToHost -Certificate $oCertificate -SkipChainCheck
    } else {
        Write-Warning 'The certificate could not be loaded from the CA database.'
    }
    Write-Host '------------------------ PKI request / report ------------------------' -ForegroundColor Blue
    foreach ($sProperty in @('CAName', 'RequestID', 'RequesterName', 'CertificateTemplate', 'SubmittedWhen', 'ResolvedWhen',
        'IssuedOn', 'CommonName', 'SAN', 'NotAfter', 'DaysRemaining', 'SerialNumber', 'CertificateHash', 'RevocationStatus', 'RevocationDetails')) {
        Write-Field -Name $sProperty -Value $CertificateRecord.$sProperty
    }
    Write-Host ''

    $aActions = @()
    if ($bHasCertificate) {
        $aActions = @(
            [PSCustomObject]@{ Id = 'Renew'; Text = 'Renew this certificate (review the prefilled request)' }
            [PSCustomObject]@{ Id = 'CSR'; Text = 'Create only a CSR from this certificate' }
            [PSCustomObject]@{ Id = 'Windows'; Text = 'Open in the Windows certificate viewer' }
            [PSCustomObject]@{ Id = 'OpenSSL'; Text = 'Show the full details (OpenSSL)' }
        )
    }
    while ($true) {
        $oAction = Select-CLIDialogObjectInArray -Objects $aActions `
            -SelectedColumns @{ l = 'Action'; e = { $_.Text } } -SelectHeaderMessage 'What do you want to do?' `
            -OtherMenuItems @(
                New-CLIDialogButton -Text '&Back' -Back
                New-CLIDialogButton -Text '&Exit' -Exit
            ) -EmptyArrayMessage 'No certificate is available for renewal.' `
            -FooterMessage '' -SeparatorColor Blue -HeaderTextInSeparator -Space -DontShowPageNumberWhenOnlyOnePage
        if (Test-DialogAction $oAction -Action 'Exit') { return $oAction }
        if (Test-DialogAction $oAction) { return }
        $oActionResult = $null
        switch ($oAction.Value.Id) {
            'Renew' {
                $oActionResult = New-PKISignedCertAndPFX_CLI -OpenSSLPath $OpenSSLPath -ItemsMode `
                    -InitialValues (ConvertTo-CertFormValues -Certificate $oCertificate)
            }
            'CSR' {
                $oActionResult = New-CSR_CLI -OpenSSLPath $OpenSSLPath -ItemsMode `
                    -InitialValues (ConvertTo-CertFormValues -Certificate $oCertificate)
            }
            'Windows' { Show-CertificateInWindowsViewer -Certificate $oCertificate }
            'OpenSSL' { Show-CertificateOpenSSLText -Certificate $oCertificate -OpenSSLPath $OpenSSLPath }
        }
        if (Test-DialogAction $oActionResult -Action 'Exit') { return $oActionResult }
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

function Read-CertificateSourceChoice {
    # Returns "Renew", "New", "Existing", or $null when the user goes back
    Param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$CurrentCertificate
    )
    $sHeader = "Which certificate do you want to deploy?"
    if ($CurrentCertificate) {
        $sState = if ($CurrentCertificate.NotAfter -lt (Get-Date)) { "expired on" } else { "expires on" }
        $sHeader = "Current certificate $sState $($CurrentCertificate.NotAfter). $sHeader"
    }
    $aChoices = @()
    if ($CurrentCertificate) {
        $aChoices += [pscustomobject]@{ Id = "Renew"; Text = "Renew with the same parameters (subject and SAN of the current certificate)" }
        $aChoices += [pscustomobject]@{ Id = "New"; Text = "Generate a new certificate (form pre-filled from the current one)" }
    } else {
        $aChoices += [pscustomobject]@{ Id = "New"; Text = "Generate a new certificate with the PKI" }
    }
    $aChoices += [pscustomobject]@{ Id = "Existing"; Text = "Use an existing PFX" }

    $oResult = Select-CLIDialogObjectInArray -Objects $aChoices `
        -SelectedColumns @{ l = "Option"; e = { $_.Text } } `
        -SelectHeaderMessage $sHeader `
        -OtherMenuItems @(New-CLIDialogButton -Text "&Back" -Back) `
        -FooterMessage "" -SeparatorColor ([System.ConsoleColor]::Blue) `
        -HeaderTextInSeparator -Space -DontShowPageNumberWhenOnlyOnePage
    if (-not $oResult -or ($oResult.PSTypeNames -and $oResult.PSTypeNames[0] -like "DialogResult.Action.*")) { return $null }
    return $oResult.Value.Id
}

function New-RenewalCSR {
    # Builds a CSR (same shape as Read-CSR output) that reuses the subject and SAN of a certificate.
    # CA and template come from the most recent working folder generated for the same CN; when none
    # is found they are asked. Only the private key password is always asked.
    # Returns @{ CSR; MoreInfo }, a DialogResult.Action.Back, or $null on error.
    Param(
        [Parameter(Mandatory)]
        [hashtable]$FormValues
    )
    $hCertObj = $FormValues.CertAndSAN.CertificateObject
    $hSAN = $FormValues.CertAndSAN.SAN
    $sCN = $hCertObj.CommonName
    if (-not $sCN) {
        Write-Host "The current certificate has no Common Name: use 'Generate a new certificate' instead." -ForegroundColor Yellow
        return New-DialogResultAction -Action "Back"
    }

    # 1. CA and template: reuse the previous request made for this CN, if any
    $sCAName = $null; $sTemplate = $null; $sPKIServer = $null; $sPrevFolder = $null
    $sCNRegex = "(^|,\s*)CN=" + [regex]::Escape($sCN) + "(,|$)"
    foreach ($oDir in (Get-ChildItem -Path (Get-ScriptDir -WorkingDir) -Directory | Sort-Object LastWriteTime -Descending)) {
        $oInfo = Get-CertInfo -CertFolder $oDir.FullName
        if (-not ($oInfo -and $oInfo.CSR -and $oInfo.MoreInfo -and $oInfo.MoreInfo.CAName)) { continue }
        if (($oInfo.CSR.CommonName -eq $sCN) -or ($oInfo.CSR.Subject -match $sCNRegex)) {
            $sCAName = $oInfo.MoreInfo.CAName
            $sTemplate = $oInfo.CSR.CertificateTemplate
            $sPKIServer = $oInfo.MoreInfo.PKIServer
            $sPrevFolder = $oDir.Name
            break
        }
    }
    if (-not $sCAName) {
        Write-Host "No previous request found for $sCN in the working folders: please choose the CA and the template." -ForegroundColor Yellow
        $oCA = if ($ScriptConfig.CAFilter) { Read-CA $ScriptConfig.CAFilter } else { Read-CA }
        if ($null -ne $oCA -and $oCA.PSObject.TypeNames[0] -eq "DialogResult.Action.Back") { return $oCA }
        if (-not (($null -ne $oCA) -and ($oCA.PSObject.TypeNames[0] -eq "ADcertificationAuthority"))) {
            Write-Host "No certificate authority selected." -ForegroundColor Yellow
            return New-DialogResultAction -Action "Back"
        }
        $sCAName = $oCA.Name
        $oTemplate = if ($ScriptConfig.TemplateFilter) {
            Read-TemplateName -CA $sCAName -TemplateFilter $ScriptConfig.TemplateFilter
        } else {
            Read-TemplateName -CA $sCAName
        }
        if ($null -ne $oTemplate -and $oTemplate.PSObject.TypeNames[0] -eq "DialogResult.Action.Back") { return $oTemplate }
        if (($oTemplate -is [hashtable]) -and $oTemplate.CertificateTemplate) { $sTemplate = $oTemplate.CertificateTemplate }
    }
    if (-not $sPKIServer) {
        $sPKIServer = (Get-CAEnrollmentServices -NameFilter ("^" + $sCAName + "$")).DNSHostName
    }
    if (-not $sPKIServer) {
        Write-Host "Could not resolve the PKI server for CA '$sCAName'." -ForegroundColor Red
        return $null
    }

    # 2. Summary and confirmation
    Write-Host ""
    Write-Host "------------------------ Certificate renewal ------------------------" -ForegroundColor Blue
    foreach ($k in $hCertObj.Keys) {
        if ($hCertObj[$k]) { Write-Host ("{0,-20}: {1}" -f $k, $hCertObj[$k]) }
    }
    Write-Host ("{0,-20}: {1}" -f "SAN (DNS)", (@($hSAN.SANdns) -join ", "))
    if ($hSAN.SANipaddress) { Write-Host ("{0,-20}: {1}" -f "SAN (IP)", (@($hSAN.SANipaddress) -join ", ")) }
    Write-Host ("{0,-20}: {1}" -f "CA", $sCAName)
    Write-Host ("{0,-20}: {1}" -f "Template", $(if ($sTemplate) { $sTemplate } else { "(none)" }))
    if ($sPrevFolder) { Write-Host ("{0,-20}: {1}" -f "CA/template from", $sPrevFolder) -ForegroundColor DarkGray }
    Write-Host "---------------------------------------------------------------------" -ForegroundColor Blue
    $sConfirm = Invoke-YesNoCLIDialog -YN -Vertical -Message "Generate the new certificate with these parameters?" `
        -YesButtonText "&Yes, generate it" -NoButtonText "&No, go back"
    if ($sConfirm -ne "Yes") { return New-DialogResultAction -Action "Back" }

    # 3. Private key password, then the working folder (named after the CN, no dialog)
    $hKey = Read-KeyPassword -AllowBack
    if ($hKey.PSTypeNames -and $hKey.PSTypeNames[0] -like "DialogResult.Action.*") { return $hKey }
    $hFiles = Read-FileNames -FriendlyName $sCN

    $hCSR = @{}
    foreach ($k in $hCertObj.Keys) { $hCSR[$k] = $hCertObj[$k] }
    foreach ($k in $hSAN.Keys) { $hCSR[$k] = $hSAN[$k] }
    if ($sTemplate) { $hCSR.CertificateTemplate = $sTemplate }
    foreach ($k in $hKey.Keys) { $hCSR[$k] = $hKey[$k] }
    foreach ($k in $hFiles.Keys) { $hCSR[$k] = $hFiles[$k] }
    return @{
        CSR      = $hCSR
        MoreInfo = @{ PKIServer = $sPKIServer; CAName = $sCAName }
    }
}

function Write-RDSCertificateInfo {
    Param(
        [Parameter(Mandatory)]
        [object]$RDSCertInfo,
        [string]$Title = "Current RDS certificates"
    )
    Write-Host ""
    Write-Host ("---- {0} on {1} ({2} mode) ----" -f $Title, $RDSCertInfo.ComputerName, $RDSCertInfo.DeploymentMode) -ForegroundColor Blue
    $RDSCertInfo.Certificates |
        Select-Object Role, Level, Subject, @{ l = "Expires"; e = { $_.NotAfter } }, Thumbprint |
        Format-Table -AutoSize | Out-String | Write-Host
}

function Read-RDSRoles {
    # Broker mode only: let the user pick which RDS roles receive the new certificate.
    Param(
        [object[]]$CurrentCertificates
    )
    $aRoles = [ordered]@{
        RDGateway    = "RD &Gateway"
        RDWebAccess  = "RD &Web Access"
        RDPublishing = "RD &Publishing"
        RDRedirector = "RD &Redirector (Connection Broker SSO)"
    }
    $cSep = [System.ConsoleColor]::Blue
    $cHint = Get-CLIDialogTheme "HintColor"
    while ($true) {
        $aLines = @()
        $aLines += New-CLIDialogSeparator -AutoLength -Text "Roles to update" -ForegroundColor $cSep
        foreach ($sRole in $aRoles.Keys) {
            $oCurrent = $CurrentCertificates | Where-Object { $_.Role -eq $sRole } | Select-Object -First 1
            # Gateway / Web Access can only be set when a server of the deployment holds the role
            if ($oCurrent -and ($oCurrent.Available -eq $false)) { continue }
            $sSuffix = if ($oCurrent -and $oCurrent.NotAfter) { "   (current cert expires $($oCurrent.NotAfter))" } else { "   (not configured)" }
            $aLines += New-CLIDialogCheckBox -Name $sRole -Text ($aRoles[$sRole] + $sSuffix) -Enabled $true -AddNewLine
        }
        $aLines += New-CLIDialogText -Text "The same certificate is usually applied to all roles." -ForegroundColor $cHint -AddNewLine
        $aLines += New-CLIDialogSeparator -AutoLength -ForegroundColor $cSep
        $aLines += New-CLIDialogObjectsRow -Header " " -Prefix "  " -FocusedPrefix "> " -HeaderSeparator "  " -Row @(
            New-CLIDialogButton -Text "&Ok" -Validate
            New-CLIDialogButton -Text "&Back" -Back
        )
        $oDialogResult = Invoke-CLIDialog -InputObject $aLines -Validate -ErrorDetails
        if ($oDialogResult.Action -eq "Back") { return New-DialogResultAction -Action "Back" }
        if ($oDialogResult.Action -ne "Validate") { return $null }
        $hForm = $oDialogResult.DialogResult.Form.GetValue($true)
        $aSelected = @($aRoles.Keys | Where-Object { $hForm.Contains($_) -and [bool]$hForm[$_] })
        if ($aSelected.Count -gt 0) { return $aSelected }
        Write-Host "Please select at least one role." -ForegroundColor Yellow
    }
}

function Get-DeploymentPfx_CLI {
    # Shared by the "Change the certificate of an application server" menus (RDS, SQL Server):
    # asks where the certificate comes from (renewal, new PKI request or existing PFX), produces
    # or selects the PFX, opens it with its password and checks it holds a private key.
    # Returns @{ PfxPath; Password; Certificate }, or nothing when the user goes back or on failure.
    Param(
        [Parameter(Mandatory)]
        [string]$ServerName,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$CurrentCertificate,
        [string]$OpenSSLPath
    )
    $sPfxPath = $null
    $ssPfxPwd = $null
    while (-not $sPfxPath) {
        $sChoice = Read-CertificateSourceChoice -CurrentCertificate $CurrentCertificate
        if (-not $sChoice) { return }
        # (if/elseif rather than switch: "continue" inside a switch would not loop the while)
        if ($sChoice -eq "Existing") {
            $oSel = Select-CLIFileFromFolder -Path (Get-ScriptDir -WorkingDir) -Filter "*.pfx" -Recurse -ColumnName "Folder" -AllowOtherFile -AllowBack `
                -SelectHeaderMessage "Select the PFX to deploy on $ServerName (or choose another file)" `
                -OtherFilePromptText "Enter the path to the PFX file to deploy" `
                -EmptyArrayMessage "No PFX found in the working folders - use 'Select Another File'" `
                -SeparatorColor Blue
            if (-not $oSel -or ($oSel.PSTypeNames -and $oSel.PSTypeNames[0] -eq "DialogResult.Action.Back")) { continue }
            if ($oSel.Value) { $sPfxPath = $oSel.Value.FullName }
            continue
        } elseif ($sChoice -eq "Renew") {
            $hPrebuilt = New-RenewalCSR -FormValues (ConvertTo-CertFormValues -Certificate $CurrentCertificate)
            if ($null -eq $hPrebuilt) { return }
            if ($hPrebuilt.PSTypeNames -and $hPrebuilt.PSTypeNames[0] -like "DialogResult.Action.*") { continue }
            $oPfx = New-PKISignedCertAndPFX_CLI -OpenSSLPath $OpenSSLPath -ItemsMode -PrebuiltCSR $hPrebuilt -ForWindowsStore
        } else {
            $hInit = if ($CurrentCertificate) {
                ConvertTo-CertFormValues -Certificate $CurrentCertificate
            } else {
                @{ CertAndSAN = @{
                    CertificateObject = [ordered]@{ CommonName = $ServerName; Organisation = ""; OrganisationalUnit = ""; Locality = ""; State = ""; CountryCode = "" }
                    SAN = @{ SANdns = @($ServerName) }
                } }
            }
            $oPfx = New-PKISignedCertAndPFX_CLI -OpenSSLPath $OpenSSLPath -ItemsMode -InitialValues $hInit -ForWindowsStore
        }
        # Renew / New: Back in the wizard returns to the choice, a failure stops here
        if ($oPfx -and $oPfx.PSTypeNames -and $oPfx.PSTypeNames[0] -like "DialogResult.Action.*") { continue }
        if (-not ($oPfx -and $oPfx.PfxPath)) {
            Write-Host "The certificate was not generated, nothing has been deployed." -ForegroundColor Red
            Write-Host ""
            return
        }
        $sPfxPath = $oPfx.PfxPath
        $ssPfxPwd = $oPfx.Password
    }

    # PFX password, validated by actually opening the PFX (skipped when we just generated it)
    $oNewCert = $null
    if ($ssPfxPwd) {
        $pBSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ssPfxPwd)
        try {
            $oNewCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                $sPfxPath, [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($pBSTR))
        } catch {
            $oNewCert = $null
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pBSTR)
        }
    }
    while (-not $oNewCert) {
        $ssPfxPwd = Read-Host -AsSecureString -Prompt "PFX password (leave empty if none)"
        $pBSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ssPfxPwd)
        try {
            $sPlain = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($pBSTR)
            $oNewCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sPfxPath, $sPlain)
            break
        } catch {
            Write-Host "Cannot open the PFX with this password. Please try again." -ForegroundColor Red
        } finally {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pBSTR)
        }
    }
    if (-not $oNewCert.HasPrivateKey) {
        Write-Host "This PFX does not contain a private key: it cannot be deployed on a server." -ForegroundColor Red
        Write-Host ""
        return
    }
    return [pscustomobject]@{
        PfxPath     = $sPfxPath
        Password    = $ssPfxPwd
        Certificate = $oNewCert
    }
}

function Write-DeploymentCertificateCheck {
    # Shows the certificate about to be deployed and warns when it does not look right for the
    # server: expired, chain not valid on this computer, server name missing from the SAN, and
    # (CheckServerAuthentication) usages that do not allow TLS server authentication.
    Param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)]
        [string]$ServerName,
        [string]$ChainHint,             # product-specific advice shown when the chain does not validate
        [switch]$CheckServerAuthentication
    )
    $oNewCert = $Certificate
    $aDNS = @(Get-CertificateSAN -Certificate $oNewCert -AsList | Where-Object { $_.Type -eq "DNS_NAME" } | ForEach-Object { $_.Value })
    Write-Host ""
    Write-Host "------------------------ Certificate to deploy ------------------------" -ForegroundColor Blue
    Write-Host ("Subject`t`t: {0}" -f $oNewCert.Subject)
    Write-Host ("SAN (DNS)`t: {0}" -f ($aDNS -join ", "))
    Write-Host ("Issuer`t`t: {0}" -f $oNewCert.Issuer)
    Write-Host ("Valid`t`t: {0} -> {1}" -f $oNewCert.NotBefore, $oNewCert.NotAfter)
    Write-Host ("Thumbprint`t: {0}" -f $oNewCert.Thumbprint)
    Write-Host "-----------------------------------------------------------------------" -ForegroundColor Blue
    if ($oNewCert.NotAfter -lt (Get-Date)) {
        Write-Host "Warning: this certificate is expired." -ForegroundColor Yellow
    }
    try {
        $oChain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
        $oChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $oChain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        if (-not $oChain.Build($oNewCert)) {
            Write-Host "Warning: the certificate chain does not validate on this computer:" -ForegroundColor Yellow
            foreach ($oElement in $oChain.ChainElements) {
                foreach ($oStatus in $oElement.ChainElementStatus) {
                    Write-Host ("  {0} : {1}" -f $oElement.Certificate.Subject, $oStatus.StatusInformation.Trim()) -ForegroundColor Yellow
                }
            }
            if ($ChainHint) { Write-Host "  $ChainHint" -ForegroundColor Yellow }
        }
    } catch {
        Write-Verbose "Chain check failed: $_"
    }
    # Matches the entered name as-is (wildcards in SAN are honoured by -like), or a short
    # name entered for a server whose FQDN is in the SAN (e.g. "rds01" vs "rds01.contoso.com").
    $bNameMatch = $false
    foreach ($sName in $aDNS) {
        if (($ServerName -like $sName) -or ($sName -like "$ServerName.*")) {
            $bNameMatch = $true
            break
        }
    }
    if (-not $bNameMatch) {
        Write-Host "Warning: '$ServerName' is not listed in the certificate SAN. Clients may show a name mismatch warning." -ForegroundColor Yellow
    }
    if ($CheckServerAuthentication) {
        foreach ($oExt in $oNewCert.Extensions) {
            if (($oExt -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) -and
                (@($oExt.EnhancedKeyUsages | ForEach-Object { $_.Value }) -notcontains "1.3.6.1.5.5.7.3.1")) {
                Write-Host "Warning: the certificate does not have the 'Server Authentication' usage (1.3.6.1.5.5.7.3.1)." -ForegroundColor Yellow
            }
            if (($oExt -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]) -and
                ($oNewCert.PublicKey.Oid.Value -eq "1.2.840.113549.1.1.1") -and
                -not ($oExt.KeyUsages -band [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment)) {
                Write-Host "Warning: the RSA key usage does not include 'Key Encipherment'." -ForegroundColor Yellow
            }
        }
    }
    Write-Host ""
}

function Set-RDSCertificate_CLI {
    # Change the certificate used by a Remote Desktop Services server:
    #   - Connection Broker deployment: Set-RDCertificate on the chosen roles
    #   - Standalone Session Host: import into LocalMachine\My and bind to the RDP-tcp listener
    # The actual work is done by the PSSomeRDSThings module (Get-/Set-RDSCertificate).

    # 1. Target server
    $sServerRegex = "(" + (Get-DNSRegex -FullLine) + ")|(" + (Get-IPRegex -FullLine) + ")"
    $hServerParams = @{
        Header           = "RDS server to update (in a Connection Broker deployment, enter the broker)"
        PropertyName     = "Server"
        ValidationMethod = $sServerRegex
        ErrorMessage     = "Please enter a valid server name or IP address"
        AllowCancel      = $true
    }
    if ($Global:RDSServer) { $hServerParams.DefaultValue = $Global:RDSServer }
    $oServer = Read-CLIDialogValidatedValue @hServerParams
    if ($null -eq $oServer -or ($oServer.PSTypeNames -and $oServer.PSTypeNames[0] -like "DialogResult.Action.*")) { return }
    $sServer = ([string]$oServer.Value).Trim()
    $Global:RDSServer = $sServer

    # 2. Connect (reuse the PKI credential as a starting point, admins often use the same account)
    if ($Global:RDSSession -and ($Global:RDSSession.ComputerName -ne $sServer)) {
        Remove-PSSession -Session $Global:RDSSession -ErrorAction SilentlyContinue
        $Global:RDSSession = $null
    }
    $oCredential = if ($Global:RDSCredential) { $Global:RDSCredential } else { $Global:PKICredential }
    $oConnect = Connect-CLIDialogPSSession -ComputerName $sServer -Credential $oCredential -Session $Global:RDSSession `
        -Message "Please provide administrator credentials to connect to" -AllowCancel
    if ($null -eq $oConnect -or ($oConnect.PSTypeNames -and $oConnect.PSTypeNames[0] -like "DialogResult.Action.*")) { return }
    $Global:RDSCredential = $oConnect.Credential
    $Global:RDSSession = $oConnect.Session

    # 3. Detect deployment mode and show the certificates currently in use
    Write-Host "Reading RDS configuration on $sServer ..." -ForegroundColor Cyan
    try {
        $sMode = Get-RDSDeploymentMode -Session $Global:RDSSession -ErrorAction Stop
        $oBefore = Get-RDSCertificate -Session $Global:RDSSession -DeploymentMode $sMode -Credential $Global:RDSCredential -ErrorAction Stop
    } catch {
        Write-Host "Unable to read the RDS configuration: $_" -ForegroundColor Red
        if ($_.InvocationInfo.PositionMessage) { Write-Host $_.InvocationInfo.PositionMessage -ForegroundColor DarkGray }
        if ($_.ScriptStackTrace) { Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray }
        Write-Host ""
        return
    }
    Write-RDSCertificateInfo -RDSCertInfo $oBefore
    if ($sMode -eq "Standalone") {
        Write-Host "No Connection Broker detected: the certificate will be bound to the RDP-tcp listener." -ForegroundColor Yellow
        Write-Host "If this server belongs to a broker deployment, run this menu against the broker instead." -ForegroundColor Yellow
        Write-Host ""
    }

    # 4. Certificate to deploy: renewal, new request or existing PFX (shared with the other servers)
    $oCurrentX509 = $null
    $oCurrentInfo = $oBefore.Certificates | Where-Object { $_.RawData } | Select-Object -First 1
    if ($oCurrentInfo) {
        try {
            $oCurrentX509 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,[byte[]]@($oCurrentInfo.RawData))
        } catch {
            Write-Verbose "Could not parse the current certificate: $_"
        }
    }
    $oPfx = Get-DeploymentPfx_CLI -ServerName $sServer -CurrentCertificate $oCurrentX509 -OpenSSLPath $OpenSSLPath
    if (-not $oPfx) { return }
    $sPfxPath = $oPfx.PfxPath
    $ssPfxPwd = $oPfx.Password
    $oNewCert = $oPfx.Certificate

    # 5. Show the new certificate and warn when it does not look right for this server.
    # RDP clients check the whole chain, revocation included, to accept signed RDP files (RD
    # Publishing): an expired or unreachable CRL makes RemoteApps fail to start.
    Write-DeploymentCertificateCheck -Certificate $oNewCert -ServerName $sServer `
        -ChainHint "RDP clients may refuse signed RemoteApp files (check that the CRLs of the chain are published and not expired)."

    # 6. Broker mode: choose the roles
    $hSetParams = @{
        Session        = $Global:RDSSession
        PfxPath        = $sPfxPath
        Password       = $ssPfxPwd
        DeploymentMode = $sMode
        Credential     = $Global:RDSCredential
    }
    $sTarget = "the RDP-tcp listener"
    if ($sMode -eq "Broker") {
        $aRoles = Read-RDSRoles -CurrentCertificates $oBefore.Certificates
        if ($null -eq $aRoles -or ($aRoles.PSTypeNames -and $aRoles.PSTypeNames[0] -like "DialogResult.Action.*")) { return }
        $hSetParams.Roles = $aRoles
        $sTarget = "these roles: " + ($aRoles -join ", ")
    }

    # 7. Confirm and deploy
    $sConfirm = Invoke-YesNoCLIDialog -YN -Vertical -Message "Deploy this certificate on $sServer for $sTarget ?" `
        -YesButtonText "&Yes, deploy it" -NoButtonText "&No, cancel"
    if ($sConfirm -ne "Yes") { return }

    Write-Host "Deploying certificate on $sServer ..." -ForegroundColor Cyan
    $oResult = try {
        Set-RDSCertificate @hSetParams -ErrorAction Stop
    } catch {
        Write-Host "Deployment failed: $_" -ForegroundColor Red
        if ($_.ScriptStackTrace) { Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray }
        Write-Host ""
        return
    }
    foreach ($oRole in $oResult.RoleResults) {
        if ($oRole.Success) {
            Write-Host ("  [OK]     {0}" -f $oRole.Role) -ForegroundColor Green
            if ($oRole.Warning) { Write-Host ("           {0}" -f $oRole.Warning) -ForegroundColor Yellow }
        } else {
            Write-Host ("  [FAILED] {0} : {1}" -f $oRole.Role, $oRole.Error) -ForegroundColor Red
        }
    }
    if ($oResult.Success) {
        Write-Host "Certificate deployed successfully." -ForegroundColor Green
    } else {
        Write-Host "Some roles could not be updated." -ForegroundColor Red
    }

    # 8. Show the resulting configuration
    try {
        $oAfter = Get-RDSCertificate -Session $Global:RDSSession -DeploymentMode $sMode -Credential $Global:RDSCredential -ErrorAction Stop
        Write-RDSCertificateInfo -RDSCertInfo $oAfter -Title "RDS certificates after update"
    } catch {
        Write-Host "Unable to read back the RDS configuration: $_" -ForegroundColor Yellow
        Write-Host ""
    }
}

function Set-MSSqlCertificate_CLI {
    # Change (renew) the TLS certificate of a SQL Server instance. Only the certificate changes:
    # the encryption settings (ForceEncryption...) are left as they are.
    # SQL Server reads its certificate when the service starts: the certificate is prepared without
    # interruption, then the instance is restarted now or later, as the user chooses.
    # The work on the server is done by the PSSomeMSSqlThings module.
    # Returns a DialogResult.Action.Exit when the user chose Exit, nothing otherwise.
    $cSep = [System.ConsoleColor]::Blue
    $sFallbackSubject = "CN=SSL_Self_Signed_Fallback"

    # 1. Target server
    $sServerRegex = "(" + (Get-DNSRegex -FullLine) + ")|(" + (Get-IPRegex -FullLine) + ")"
    $hServerParams = @{
        Header           = "SQL Server computer to update"
        PropertyName     = "Server"
        ValidationMethod = $sServerRegex
        ErrorMessage     = "Please enter a valid server name or IP address"
        AllowCancel      = $true
    }
    if ($Global:MSSqlServer) { $hServerParams.DefaultValue = $Global:MSSqlServer }
    $oServer = Read-CLIDialogValidatedValue @hServerParams
    if (Test-DialogAction $oServer) { return }
    $sServer = ([string]$oServer.Value).Trim()
    $Global:MSSqlServer = $sServer

    # 2. Connect (reuse the RDS / PKI credential as a starting point, admins often use the same account)
    if ($Global:MSSqlSession -and ($Global:MSSqlSession.ComputerName -ne $sServer)) {
        Remove-PSSession -Session $Global:MSSqlSession -ErrorAction SilentlyContinue
        $Global:MSSqlSession = $null
    }
    $oCredential = if ($Global:MSSqlCredential) { $Global:MSSqlCredential } elseif ($Global:RDSCredential) { $Global:RDSCredential } else { $Global:PKICredential }
    $oConnect = Connect-CLIDialogPSSession -ComputerName $sServer -Credential $oCredential -Session $Global:MSSqlSession `
        -Message "Please provide administrator credentials to connect to" -AllowCancel
    if (Test-DialogAction $oConnect) { return }
    $Global:MSSqlCredential = $oConnect.Credential
    $Global:MSSqlSession = $oConnect.Session

    while ($true) {
        # 3. Instances, with the certificate configured and the one presented on the network
        Write-Host "Reading SQL Server instances on $sServer ..." -ForegroundColor Cyan
        $aInstances = try {
            @(Get-MSSqlInstance -Session $Global:MSSqlSession -ErrorAction Stop)
        } catch {
            Write-Host "Unable to read the SQL Server instances: $_" -ForegroundColor Red
            Write-Host ""
            return
        }
        if ($aInstances.Count -eq 0) {
            Write-Host "No SQL Server instance found on $sServer." -ForegroundColor Yellow
            Write-Host ""
            return
        }
        $aRows = foreach ($oInstance in $aInstances) {
            $oConfigured = if ($oInstance.CertificateRawData) {
                New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(,[byte[]]@($oInstance.CertificateRawData))
            }
            $oPresented = $null
            if (($oInstance.ServiceState -eq "Running") -and $oInstance.TcpEnabled -and $oInstance.TcpPort) {
                $oPresented = try { Get-CertificateFromSqlServer -ComputerName $sServer -Port $oInstance.TcpPort -TimeoutSeconds 5 } catch { $null }
            }
            $sConfigured = if (-not $oInstance.CertificateThumbprint) {
                "(none)"
            } elseif (-not $oConfigured) {
                "MISSING from the store!"
            } else {
                "{0} (expires {1:yyyy-MM-dd})" -f $oConfigured.GetNameInfo("SimpleName", $false), $oConfigured.NotAfter
            }
            $sInUse = if (-not $oPresented) {
                "unknown"
            } elseif ($oPresented.Subject -eq $sFallbackSubject) {
                if ($oInstance.CertificateThumbprint) { "self-signed (restart pending)" } else { "self-signed" }
            } elseif ($oPresented.Thumbprint -eq $oInstance.CertificateThumbprint) {
                "configured one"
            } else {
                "{0} (restart pending)" -f $oPresented.GetNameInfo("SimpleName", $false)
            }
            [pscustomobject]@{
                Instance   = $oInstance.InstanceName
                State      = $oInstance.ServiceState
                Port       = if ($oInstance.TcpPort) { $oInstance.TcpPort } else { "" }
                Configured = $sConfigured
                InUse      = $sInUse
                Info       = $oInstance
                ConfiguredCertificate = $oConfigured
                PresentedCertificate  = $oPresented
            }
        }

        # 4. Instance to update
        $oSel = Select-CLIDialogObjectInArray -Objects @($aRows) `
            -SelectedColumns @(
                @{ l = "Instance"; e = { $_.Instance } }, @{ l = "State"; e = { $_.State } }, @{ l = "Port"; e = { $_.Port } },
                @{ l = "Configured certificate"; e = { $_.Configured } }, @{ l = "Presented on the network"; e = { $_.InUse } }
            ) `
            -SelectHeaderMessage "Which instance of $sServer do you want to update?" `
            -OtherMenuItems @(
                New-CLIDialogButton -Text "&Back" -Back
                New-CLIDialogButton -Text "&Exit" -Exit
            ) `
            -FooterMessage "" -SeparatorColor $cSep -HeaderTextInSeparator -Space -DontShowPageNumberWhenOnlyOnePage
        if (Test-DialogAction $oSel -Action "Exit") { return $oSel }
        if (Test-DialogAction $oSel) { return }
        $oRow = $oSel.Value
        $oInstance = $oRow.Info

        Write-Host ""
        Write-Host ("---- Instance {0} on {1} ----" -f $oInstance.InstanceName, $sServer) -ForegroundColor Blue
        Write-Host ("Version`t`t: {0} ({1})" -f $oInstance.Version, $oInstance.Edition)
        Write-Host ("Service`t`t: {0} ({1}), account {2}" -f $oInstance.ServiceName, $oInstance.ServiceState, $oInstance.ServiceAccount)
        Write-Host ("Encryption`t: {0} (not changed by this tool)" -f $(if ($oInstance.ForceEncryption) { "forced" } else { "not forced" }))
        Write-Host ("Configured`t: {0}" -f $oRow.Configured)
        Write-Host ("Presented`t: {0}" -f $oRow.InUse)
        Write-Host ""
        if ($oInstance.CertificateThumbprint -and -not $oRow.ConfiguredCertificate) {
            Write-Host "Warning: the configured certificate ($($oInstance.CertificateThumbprint)) is not in the store: the instance will not start at its next restart." -ForegroundColor Yellow
            Write-Host ""
        }

        # 5. Certificate to deploy: renewal, new request or existing PFX. The current certificate is
        #    the configured one, else the one presented (unless self-generated by SQL Server)
        $oCurrent = if ($oRow.ConfiguredCertificate) {
            $oRow.ConfiguredCertificate
        } elseif ($oRow.PresentedCertificate -and ($oRow.PresentedCertificate.Subject -ne $sFallbackSubject)) {
            $oRow.PresentedCertificate
        }
        $oPfx = Get-DeploymentPfx_CLI -ServerName $sServer -CurrentCertificate $oCurrent -OpenSSLPath $OpenSSLPath
        if (-not $oPfx) { continue }

        # 6. Checks
        Write-DeploymentCertificateCheck -Certificate $oPfx.Certificate -ServerName $sServer -CheckServerAuthentication `
            -ChainHint "Clients that validate the server certificate (TrustServerCertificate=False) will refuse the connection."

        # 7. Prepare the certificate (no interruption)
        $sConfirm = Invoke-YesNoCLIDialog -YN -Vertical `
            -Message "Prepare this certificate for instance $($oInstance.InstanceName) on $sServer ? The instance is not restarted at this step." `
            -YesButtonText "&Yes, prepare it" -NoButtonText "&No, cancel"
        if ($sConfirm -ne "Yes") { continue }
        Write-Host "Preparing the certificate on $sServer ..." -ForegroundColor Cyan
        $oResult = try {
            Set-MSSqlCertificate -Session $Global:MSSqlSession -InstanceName $oInstance.InstanceName -PfxPath $oPfx.PfxPath -Password $oPfx.Password -ErrorAction Stop
        } catch {
            [pscustomobject]@{ Success = $false; Error = "$_"; Warnings = @() }
        }
        foreach ($sWarning in $oResult.Warnings) { Write-Host "Warning: $sWarning" -ForegroundColor Yellow }
        if (-not $oResult.Success) {
            Write-Host "The certificate could not be prepared: $($oResult.Error)" -ForegroundColor Red
            Write-Host "The configuration of the instance has not been changed." -ForegroundColor Red
            Write-Host ""
            return
        }
        $sKeyAccess = switch ($oResult.KeyAccess) {
            "Granted"        { "read access granted to $($oResult.ServiceAccount)" }
            "AlreadyGranted" { "$($oResult.ServiceAccount) already had read access" }
            "NotNeeded"      { "not needed ($($oResult.ServiceAccount))" }
            default          { "$($oResult.KeyAccess)" }
        }
        Write-Host "  [OK] Certificate imported in LocalMachine\My ($($oResult.KeyStorage) key)" -ForegroundColor Green
        Write-Host "  [OK] Private key: $sKeyAccess" -ForegroundColor Green
        Write-Host "  [OK] Instance configured with $($oResult.Thumbprint)" -ForegroundColor Green
        Write-Host ""

        # 8. Restart now or later
        $sRestart = Invoke-YesNoCLIDialog -YN -Vertical `
            -Message "SQL Server uses the new certificate after a restart of the instance. Restart $($oInstance.ServiceName) now?" `
            -YesButtonText "&Restart now (connections will be cut)" -NoButtonText "&Later (at the next restart of the service)"
        if ($sRestart -ne "Yes") {
            Write-Host "The instance keeps its current certificate until $($oInstance.ServiceName) restarts." -ForegroundColor Yellow
            Write-Host ""
            return
        }
        Write-Host "Restarting $($oInstance.ServiceName) on $sServer ..." -ForegroundColor Cyan
        $oRestart = Restart-MSSqlInstance -Session $Global:MSSqlSession -InstanceName $oInstance.InstanceName
        if (-not $oRestart.Success) {
            Write-Host "The restart failed: $($oRestart.Error) (service state: $($oRestart.ServiceState))" -ForegroundColor Red
            Write-Host "Check the SQL Server ERRORLOG on $sServer." -ForegroundColor Red
            Write-Host ""
            return
        }
        $sDependents = if ($oRestart.DependentServices) { " (also restarted: $($oRestart.DependentServices -join ', '))" } else { "" }
        Write-Host "  [OK] $($oInstance.ServiceName) restarted$sDependents" -ForegroundColor Green

        # 9. Check the certificate now presented on the network (the instance may take a few seconds to listen)
        if ($oInstance.TcpEnabled -and $oInstance.TcpPort) {
            $oNow = $null
            for ($i = 0; ($i -lt 6) -and -not $oNow; $i++) {
                if ($i -gt 0) { Start-Sleep -Seconds 5 }
                $oNow = try { Get-CertificateFromSqlServer -ComputerName $sServer -Port $oInstance.TcpPort -TimeoutSeconds 5 } catch { $null }
            }
            if (-not $oNow) {
                Write-Host "Unable to read the certificate now presented on port $($oInstance.TcpPort)." -ForegroundColor Yellow
            } elseif ($oNow.Thumbprint -eq $oResult.Thumbprint) {
                Write-Host "  [OK] The instance now presents the new certificate." -ForegroundColor Green
            } else {
                Write-Host "Warning: the instance presents $($oNow.Subject) ($($oNow.Thumbprint)), not the new certificate. Check the SQL Server ERRORLOG." -ForegroundColor Yellow
            }
        }
        Write-Host ""
        return
    }
}

function Read-CertificateFile {
    # Loads every certificate held by a file: PEM (one or several blocks), DER, P7B or PFX/P12.
    # A PFX is first opened without password, then the password is asked.
    # Returns the certificates (nothing when the user gives up on the PFX password).
    Param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    $sPath = $Path.Trim().Trim('"').Trim("'")
    if (-not (Test-Path -LiteralPath $sPath -PathType Leaf)) {
        throw "Certificate file not found: $sPath"
    }
    $sPath = (Resolve-Path -LiteralPath $sPath).ProviderPath

    $oCollection = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection

    # PEM: read every block (.NET only reads the first one of a bundle). A block can hold a
    # single certificate or a PKCS#7 (the Windows PKI writes P7B files with a CERTIFICATE header).
    $sText = [System.IO.File]::ReadAllText($sPath)
    if ($sText -match '-----BEGIN (CERTIFICATE|PKCS7)-----') {
        $sPemRegex = '-----BEGIN (?:CERTIFICATE|PKCS7)-----([A-Za-z0-9+/=\s]+?)-----END (?:CERTIFICATE|PKCS7)-----'
        foreach ($oMatch in [regex]::Matches($sText, $sPemRegex)) {
            $oCollection.Import([Convert]::FromBase64String(($oMatch.Groups[1].Value -replace '\s', '')))
        }
        foreach ($oCert in $oCollection) { $oCert }
        return
    }

    $eType = try {
        [System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($sPath)
    } catch {
        [System.Security.Cryptography.X509Certificates.X509ContentType]::Unknown
    }
    if ($eType -eq [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx) {
        $sPassword = ""
        $bAsked = $false
        while ($true) {
            try {
                $oCollection.Import($sPath, $sPassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::DefaultKeySet)
                break
            } catch {
                if ($bAsked) {
                    Write-Host "Cannot open the PFX with this password." -ForegroundColor Red
                    $sRetry = Invoke-YesNoCLIDialog -YN -Message "Try another password?"
                    if ($sRetry -ne "Yes") { return }
                }
                $ssPassword = Read-Host -AsSecureString -Prompt "PFX password"
                $pBSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ssPassword)
                try {
                    $sPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($pBSTR)
                } finally {
                    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pBSTR)
                }
                $bAsked = $true
            }
        }
    } else {
        try { $oCollection.Import($sPath) } catch { Write-Verbose "Collection import failed: $_" }
        if ($oCollection.Count -eq 0) {
            # Gives a meaningful error when the file is not a certificate
            $oCollection.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($sPath))) | Out-Null
        }
    }
    foreach ($oCert in $oCollection) { $oCert }
}

function Get-CertificateFromHostRace {
    # Reads the certificate of host:port over HTTPS and SQL Server (TDS) at the same time; the first
    # attempt that returns a certificate wins. A SQL Server port may keep a TLS attempt waiting, and
    # the other way round, so trying one after the other could be slow.
    # The losing attempt is asked to stop and ends in the background (bounded by its own timeout).
    Param(
        [Parameter(Mandatory)]
        [string]$HostName,
        [Parameter(Mandatory)]
        [int]$Port
    )
    # Each attempt runs in its own runspace, with the two functions it needs
    $oIss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($sFunction in "Get-CertificateFromUrl", "Get-CertificateFromSqlServer") {
        $oIss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($sFunction, (Get-Command $sFunction).Definition)))
    }
    $sHostOnly = $HostName.Trim("[", "]")
    $aAttempts = @(
        [pscustomobject]@{ Name = "HTTPS"; Script = 'param($h, $p) Get-CertificateFromUrl -Url "https://${h}:$p"'; Host = $HostName; PS = $null; Handle = $null; Error = $null }
        [pscustomobject]@{ Name = "SQL Server"; Script = 'param($h, $p) Get-CertificateFromSqlServer -ComputerName $h -Port $p -TdsOnly'; Host = $sHostOnly; PS = $null; Handle = $null; Error = $null }
    )
    foreach ($oAttempt in $aAttempts) {
        $oAttempt.PS = [PowerShell]::Create($oIss).AddScript($oAttempt.Script).AddArgument($oAttempt.Host).AddArgument($Port)
        $oAttempt.Handle = $oAttempt.PS.BeginInvoke()
    }
    $oWinner = $null
    $oCertificate = $null
    try {
        $aPending = [System.Collections.ArrayList]@($aAttempts)
        while ($aPending.Count -gt 0 -and -not $oCertificate) {
            $iDone = [System.Threading.WaitHandle]::WaitAny([System.Threading.WaitHandle[]]@($aPending | ForEach-Object { $_.Handle.AsyncWaitHandle }))
            $oAttempt = $aPending[$iDone]
            $aPending.RemoveAt($iDone)
            try {
                $oResult = @($oAttempt.PS.EndInvoke($oAttempt.Handle) | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] })
                if ($oResult.Count -gt 0) {
                    $oCertificate = $oResult[0]
                    $oWinner = $oAttempt
                } else {
                    $oAttempt.Error = if ($oAttempt.PS.Streams.Error.Count -gt 0) { "$($oAttempt.PS.Streams.Error[0])" } else { "no certificate" }
                }
            } catch {
                $oInner = $_.Exception
                while ($oInner.InnerException) { $oInner = $oInner.InnerException }
                $oAttempt.Error = $oInner.Message
            }
        }
    } finally {
        foreach ($oAttempt in $aAttempts) {
            if ($oAttempt.Handle.IsCompleted) {
                $oAttempt.PS.Dispose()
            } else {
                $null = $oAttempt.PS.BeginStop($null, $null)
            }
        }
    }
    if (-not $oCertificate) {
        throw ("No certificate from ${HostName}:$Port. " + (($aAttempts | ForEach-Object { "$($_.Name): $($_.Error)" }) -join " / "))
    }
    Write-Host "Certificate presented over $($oWinner.Name)." -ForegroundColor Cyan
    return $oCertificate
}

function Get-CertificateFromInput {
    # Loads the certificates designated by:
    #   - a file path
    #   - an HTTPS URL
    #   - "server\instance[,port]" or "server,port": SQL Server syntaxes (without port, the port of
    #     the instance is asked to the SQL Server Browser)
    #   - "host[:port]" (port 443 by default): HTTPS and SQL Server at the same time, first answer wins
    # For a server, the certificate it presents to its clients is returned.
    Param(
        [Parameter(Mandatory)]
        [string]$InputString
    )
    $sInput = $InputString.Trim().Trim('"').Trim("'")
    if ($sInput -match '^https://.+') {
        Write-Host "Fetching certificate from $sInput ..." -ForegroundColor Cyan
        return Get-CertificateFromUrl -Url $sInput
    }
    if (Test-Path -LiteralPath $sInput -PathType Leaf) {
        return Read-CertificateFile -Path $sInput
    }
    if ($sInput -match '^(?<server>[^\\,:\s]+)(?:\\(?<instance>[^\\,:\s]+)(?:,(?<port>[0-9]{1,5}))?|,(?<port>[0-9]{1,5}))$') {
        $hSql = @{ ComputerName = $Matches.server }
        if ($Matches.instance) { $hSql.InstanceName = $Matches.instance }
        if ($Matches.port) { $hSql.Port = [int]$Matches.port }
        Write-Host "Fetching certificate from SQL Server $sInput ..." -ForegroundColor Cyan
        return Get-CertificateFromSqlServer @hSql
    }
    $oHostPort = [regex]::Match($sInput, (Get-HostPortRegex -FullLine))
    if ($oHostPort.Success) {
        $sHost = $oHostPort.Groups["Host"].Value
        $iPort = if ($oHostPort.Groups["Port"].Success) { [int]$oHostPort.Groups["Port"].Value } else { 443 }
        Write-Host "Fetching certificate from ${sHost}:$iPort (HTTPS and SQL Server at the same time) ..." -ForegroundColor Cyan
        return Get-CertificateFromHostRace -HostName $sHost -Port $iPort
    }
    throw "'$sInput' is neither an existing file, an HTTPS URL, a host[:port] nor a SQL Server instance (server\instance)"
}

function Get-SortedCertificateChain {
    # Orders a set of certificates from the leaf to the root. Duplicates are removed and the
    # certificates that are not part of the leaf's chain are appended at the end.
    Param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificates
    )
    $aCerts = @($Certificates | Where-Object { $_ } | Sort-Object -Property Thumbprint -Unique)
    if ($aCerts.Count -le 1) { return $aCerts }
    $aLeaves = @($aCerts | Where-Object {
        $oCandidate = $_
        -not ($aCerts | Where-Object { Test-CertificateIsParent -Parent $oCandidate -Child $_ })
    })
    $aOrdered = @()
    $oCurrent = if ($aLeaves.Count -gt 0) { $aLeaves[0] } else { $aCerts[0] }
    while ($oCurrent -and ($aOrdered.Count -eq 0 -or $aOrdered.Thumbprint -notcontains $oCurrent.Thumbprint)) {
        $aOrdered += $oCurrent
        $oChild = $oCurrent
        $oCurrent = $aCerts | Where-Object { Test-CertificateIsParent -Parent $_ -Child $oChild } | Select-Object -First 1
    }
    $aOrdered += @($aCerts | Where-Object { $aOrdered.Thumbprint -notcontains $_.Thumbprint })
    return $aOrdered
}

function Write-Field {
    Param(
        [string]$Name,
        [object]$Value,
        [object]$Color   # console default when not set
    )
    $aValues = @($Value | Where-Object { $null -ne $_ -and "$_" -ne "" })
    if ($aValues.Count -eq 0) { return }
    # Label in green like Format-List in PowerShell 7; continuation lines are aligned under
    # the value, without the ":"
    $sPrefix = "{0,-20}: " -f $Name
    foreach ($v in $aValues) {
        Write-Host $sPrefix -NoNewline -ForegroundColor Green
        if ($null -ne $Color) { Write-Host $v -ForegroundColor $Color } else { Write-Host $v }
        $sPrefix = " " * 22
    }
}

function Write-CertificateToHost {
    # Displays the main information of a certificate, then validates its chain on this computer
    # (ExtraCertificates are used as intermediates, e.g. the other certificates of a P7B).
    Param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]$ExtraCertificates,
        [switch]$SkipChainCheck
    )
    $oCert = $Certificate

    Write-Host ""
    Write-Host "--------------------------- Certificate ---------------------------" -ForegroundColor Blue
    Write-Field "Subject" $oCert.Subject

    # Subject alternative names: one per line, grouped by type (DNS and IP first, then the
    # others in the certificate order)
    $aSAN = @(try { Get-CertificateSAN -Certificate $oCert -AsList } catch { })
    if ($aSAN.Count -gt 0) {
        $hSANLabels = [ordered]@{ DNS_NAME = "DNS"; IP_ADDRESS = "IP"; RFC822_NAME = "Email"; USER_PRINCIPLE_NAME = "UPN"; URL = "URL" }
        $aSANLines = foreach ($sType in $hSANLabels.Keys) {
            $aSAN | Where-Object { $_.Type -eq $sType } | ForEach-Object { "{0,-6}{1}" -f $hSANLabels[$sType], $_.Value }
        }
        $aSANLines += @($aSAN | Where-Object { -not $hSANLabels.Contains($_.Type) } | ForEach-Object { "{0} {1}" -f $_.Type, $_.Value })
        Write-Field "SAN ($($aSAN.Count))" $aSANLines -Color Cyan
    } else {
        Write-Field "SAN" "(none)" -Color Yellow
    }

    $bSelfSigned = ($oCert.Subject -eq $oCert.Issuer)
    Write-Field "Issuer" ($oCert.Issuer + $(if ($bSelfSigned) { "   (self-signed)" } else { "" }))
    Write-Field "Serial number" $oCert.SerialNumber
    Write-Field "Valid from" $oCert.NotBefore

    $iDaysLeft = [int][Math]::Floor(($oCert.NotAfter - (Get-Date)).TotalDays)
    $sExpiry, $cExpiry = if ($oCert.NotAfter -lt (Get-Date)) {
        ("{0}   (expired)" -f $oCert.NotAfter), [System.ConsoleColor]::Red
    } elseif ($oCert.NotBefore -gt (Get-Date)) {
        ("{0}   (not yet valid)" -f $oCert.NotAfter), [System.ConsoleColor]::Yellow
    } elseif ($iDaysLeft -lt 30) {
        ("{0}   ({1} days left)" -f $oCert.NotAfter, $iDaysLeft), [System.ConsoleColor]::Yellow
    } else {
        ("{0}   ({1} days left)" -f $oCert.NotAfter, $iDaysLeft), [System.ConsoleColor]::Green
    }
    Write-Field "Valid to" $sExpiry -Color $cExpiry

    Write-Field "Thumbprint (SHA1)" $oCert.Thumbprint
    $oSHA256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        Write-Field "SHA256" (($oSHA256.ComputeHash($oCert.RawData) | ForEach-Object { $_.ToString("X2") }) -join "")
    } finally {
        $oSHA256.Dispose()
    }

    # Public key: PublicKey.Key does not support ECC keys on .NET Framework
    $iKeySize = $null
    try {
        $iKeySize = $oCert.PublicKey.Key.KeySize
    } catch {
        try { $iKeySize = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($oCert).KeySize } catch {}
    }
    $sKeyAlgo = if ($oCert.PublicKey.Oid.FriendlyName) { $oCert.PublicKey.Oid.FriendlyName } else { $oCert.PublicKey.Oid.Value }
    Write-Field "Public key" ($sKeyAlgo + $(if ($iKeySize) { " $iKeySize bits" } else { "" }))
    Write-Field "Signature algorithm" $oCert.SignatureAlgorithm.FriendlyName

    foreach ($oExt in $oCert.Extensions) {
        if ($oExt -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]) {
            Write-Field "Key usage" $oExt.KeyUsages.ToString()
        } elseif ($oExt -is [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]) {
            $aEKU = foreach ($oOid in $oExt.EnhancedKeyUsages) {
                if ($oOid.FriendlyName) { "{0} ({1})" -f $oOid.FriendlyName, $oOid.Value } else { $oOid.Value }
            }
            Write-Field "Enhanced key usage" $aEKU
        } elseif ($oExt -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]) {
            $sBC = if ($oExt.CertificateAuthority) {
                "Certification authority" + $(if ($oExt.HasPathLengthConstraint) { " (path length $($oExt.PathLengthConstraint))" } else { "" })
            } else {
                "End entity"
            }
            Write-Field "Basic constraints" $sBC
        }
    }

    $oTemplate = Get-CertificateTemplate -Certificate $oCert -WarningAction SilentlyContinue
    if ($oTemplate -and ($oTemplate.Name -or $oTemplate.OID)) {
        $sTemplate = if ($oTemplate.Name) { $oTemplate.Name } else { $oTemplate.OID }
        if ($null -ne $oTemplate.MajorVersion) { $sTemplate += " (v$($oTemplate.MajorVersion).$($oTemplate.MinorVersion))" }
        Write-Field "Template" $sTemplate
    }
    Write-Field "Subject key ID" (Get-CertificateSKI -Certificate $oCert)
    Write-Field "Authority key ID" (Get-CertificateAKI -Certificate $oCert)
    try {
        $oURLs = Get-CertificateURL -Cert $oCert -WarningAction SilentlyContinue
        Write-Field "CRL (CDP)" $oURLs.CDP
        Write-Field "CA issuers (AIA)" $oURLs.AIA
        Write-Field "OCSP" $oURLs.OCSP
    } catch {
        Write-Verbose "Cannot read certificate URLs: $_"
    }
    Write-Field "Private key" $(if ($oCert.HasPrivateKey) { "Yes" } else { "No" })

    if ($SkipChainCheck) { return }

    # Chain validation on this computer (revocation checked online, may take a few seconds)
    Write-Host "-------------------------- Chain check ----------------------------" -ForegroundColor Blue
    $oChain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    try {
        $oChain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $oChain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $oChain.ChainPolicy.UrlRetrievalTimeout = New-TimeSpan -Seconds 15
        foreach ($oExtra in $ExtraCertificates) {
            if ($oExtra.Thumbprint -ne $oCert.Thumbprint) { $oChain.ChainPolicy.ExtraStore.Add($oExtra) | Out-Null }
        }
        $bValid = $oChain.Build($oCert)
        $sIndent = ""
        foreach ($oElement in $oChain.ChainElements) {
            $aStatus = @($oElement.ChainElementStatus | Where-Object { $_.Status -ne "NoError" })
            $sLine = "{0}{1}" -f $sIndent, $oElement.Certificate.Subject
            if ($aStatus.Count -gt 0) { Write-Host $sLine -ForegroundColor Yellow } else { Write-Host $sLine }
            foreach ($oStatus in $aStatus) {
                Write-Host ("{0}  ! {1}" -f $sIndent, $oStatus.StatusInformation.Trim()) -ForegroundColor Yellow
            }
            $sIndent += "  "
        }
        if ($bValid) {
            Write-Host "The certificate chain is valid on this computer." -ForegroundColor Green
        } else {
            Write-Host "The certificate chain does not validate on this computer." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Chain check failed: $_" -ForegroundColor Yellow
    } finally {
        $oChain.Reset()
    }
    Write-Host "-------------------------------------------------------------------" -ForegroundColor Blue
    Write-Host ""
}

function Show-CertificateInWindowsViewer {
    # Opens the certificate in the Windows certificate dialog and waits until it is closed
    Param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    $sTempFile = Join-Path ([System.IO.Path]::GetTempPath()) ($Certificate.Thumbprint + ".cer")
    [System.IO.File]::WriteAllBytes($sTempFile, $Certificate.RawData)
    Write-Host "Close the certificate window to continue..." -ForegroundColor Cyan
    try {
        # No quotes around the path: CryptExtOpenCER takes the rest of the command line as the
        # file name, quotes included (Windows registers it as "CryptExtOpenCER %1")
        Start-Process -FilePath "rundll32.exe" -ArgumentList "cryptext.dll,CryptExtOpenCER $sTempFile" -Wait
    } finally {
        Remove-Item -LiteralPath $sTempFile -Force -ErrorAction SilentlyContinue
    }
}

function Show-CertificateOpenSSLText {
    # Displays the full decoding of the certificate made by OpenSSL (all extensions, raw values)
    Param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory)]
        [string]$OpenSSLPath
    )
    $sTempFile = Join-Path ([System.IO.Path]::GetTempPath()) ($Certificate.Thumbprint + ".der")
    [System.IO.File]::WriteAllBytes($sTempFile, $Certificate.RawData)
    try {
        & $OpenSSLPath x509 -inform DER -in $sTempFile -noout -text | Out-Host
    } finally {
        Remove-Item -LiteralPath $sTempFile -Force -ErrorAction SilentlyContinue
    }
    Write-Host ""
}

function Get-CertificateFileInFolder {
    # Certificate files of a folder (PEM, DER, P7B, PFX...), optionally with its subfolders
    Param(
        [Parameter(Mandatory)]
        [string]$Path,
        [switch]$Recurse
    )
    $aExtensions = @(".cer", ".crt", ".pem", ".der", ".p7b", ".p7c", ".pfx", ".p12")
    Get-ChildItem -LiteralPath $Path -File -Recurse:$Recurse -ErrorAction SilentlyContinue |
        Where-Object { $aExtensions -contains $_.Extension.ToLower() }
}

function Test-DialogAction {
    # True when $Result is a dialog action (Back, Exit...) or nothing; -Action narrows to one action
    Param(
        [object]$Result,
        [string]$Action = "*"
    )
    if ($null -eq $Result) { return ($Action -eq "*") }
    return [bool]($Result.PSTypeNames -and $Result.PSTypeNames[0] -like "DialogResult.Action.$Action")
}

function Show-CertificateSource_CLI {
    # Loads a certificate source (file path, HTTPS URL or host[:port]), lets the user pick the
    # certificate when the source holds several, displays it and offers more views.
    # Returns a DialogResult.Action.Exit when the user chose Exit, nothing on Back.
    Param(
        [Parameter(Mandatory)]
        [string]$Source,
        [string]$OpenSSLPath
    )
    $cSep = [System.ConsoleColor]::Blue
    $aNavButtons = @(
        New-CLIDialogButton -Text "&Back" -Back
        New-CLIDialogButton -Text "&Exit" -Exit
    )

    $aCerts = try {
        @(Get-SortedCertificateChain -Certificates @(Get-CertificateFromInput -InputString $Source))
    } catch {
        Write-Host "Failed to load the certificate: $_" -ForegroundColor Red
        Write-Host ""
        return
    }
    if ($aCerts.Count -eq 0) {
        Write-Host "No certificate found." -ForegroundColor Yellow
        Write-Host ""
        return
    }

    while ($true) {
        # Several certificates (P7B, PEM bundle, PFX with its chain): choose one
        $oCert = if ($aCerts.Count -eq 1) {
            $aCerts[0]
        } else {
            $aItems = for ($i = 0; $i -lt $aCerts.Count; $i++) {
                $sRole = if ($i -eq 0) { "Leaf" } elseif ($aCerts[$i].Subject -eq $aCerts[$i].Issuer) { "Root" } else { "CA" }
                [pscustomobject]@{ Index = $i; Role = $sRole; Subject = $aCerts[$i].Subject; Expires = $aCerts[$i].NotAfter.ToString("yyyy-MM-dd") }
            }
            $oCertSel = Select-CLIDialogObjectInArray -Objects @($aItems) `
                -SelectedColumns @(@{ l = "Role"; e = { $_.Role } }, @{ l = "Subject"; e = { $_.Subject } }, @{ l = "Expires"; e = { $_.Expires } }) `
                -SelectHeaderMessage "$($aCerts.Count) certificates in this file, which one do you want to view?" `
                -OtherMenuItems $aNavButtons `
                -FooterMessage "" -SeparatorColor $cSep -HeaderTextInSeparator -Space -DontShowPageNumberWhenOnlyOnePage
            if (Test-DialogAction $oCertSel -Action "Exit") { return $oCertSel }
            if (Test-DialogAction $oCertSel) { return }
            $aCerts[$oCertSel.Value.Index]
        }

        Write-CertificateToHost -Certificate $oCert -ExtraCertificates $aCerts

        # DNS and IP SAN: the ones the certificate request form accepts
        $aRequestSAN = @(Get-CertificateSAN -Certificate $oCert -AsList | Where-Object { $_.Type -in "DNS_NAME", "IP_ADDRESS" } | ForEach-Object { $_.Value })
        $aActions = @(
            [pscustomobject]@{ Id = "NewCert"; Text = "Create a new certificate from this one (subject and SAN pre-filled)" }
            [pscustomobject]@{ Id = "NewCSR"; Text = "Create only a CSR from this one (subject and SAN pre-filled)" }
        )
        if ($aRequestSAN.Count -gt 0) {
            $aActions += [pscustomobject]@{ Id = "CopySAN"; Text = "Copy the DNS / IP SAN to the clipboard (one per line)" }
        }
        $aActions += @(
            [pscustomobject]@{ Id = "Windows"; Text = "Open in the Windows certificate viewer" }
            [pscustomobject]@{ Id = "OpenSSL"; Text = "Show the full details (OpenSSL)" }
        )
        while ($true) {
            $oAction = Select-CLIDialogObjectInArray -Objects $aActions `
                -SelectedColumns @{ l = "Action"; e = { $_.Text } } `
                -SelectHeaderMessage "What do you want to do?" `
                -OtherMenuItems $aNavButtons `
                -FooterMessage "" -SeparatorColor $cSep -HeaderTextInSeparator -Space -DontShowPageNumberWhenOnlyOnePage
            if (Test-DialogAction $oAction -Action "Exit") { return $oAction }
            if (Test-DialogAction $oAction) { break }
            switch ($oAction.Value.Id) {
                "NewCert" {
                    # Back in the wizard returns here; the result is not needed
                    $null = New-PKISignedCertAndPFX_CLI -OpenSSLPath $OpenSSLPath -ItemsMode -InitialValues (ConvertTo-CertFormValues -Certificate $oCert)
                }
                "NewCSR" {
                    $null = New-CSR_CLI -OpenSSLPath $OpenSSLPath -ItemsMode -InitialValues (ConvertTo-CertFormValues -Certificate $oCert)
                }
                "CopySAN" {
                    Set-Clipboard -Value ($aRequestSAN -join [Environment]::NewLine)
                    Write-Host "$($aRequestSAN.Count) SAN copied to the clipboard." -ForegroundColor Green
                    Write-Host ""
                }
                "Windows" { Show-CertificateInWindowsViewer -Certificate $oCert }
                "OpenSSL" { Show-CertificateOpenSSLText -Certificate $oCert -OpenSSLPath $OpenSSLPath }
            }
        }
        # Back from the certificate: to the certificate list, or out when there is only one
        if ($aCerts.Count -eq 1) { return }
    }
}

function Show-Certificate_CLI {
    # View a certificate: choose a working folder, then a certificate file of that folder.
    # "Other source" accepts any file path, an HTTPS URL or a host[:port].
    # Returns a DialogResult.Action.Exit when the user chose Exit, nothing on Back.
    Param(
        [string]$OpenSSLPath
    )
    $cSep = [System.ConsoleColor]::Blue
    $sWorkingDir = (Get-ScriptDir -WorkingDir).TrimEnd("\")

    while ($true) {
        # 1. Folders holding certificate files (and the working folder itself when it holds some)
        $aFolders = @()
        $aRootFiles = @(Get-CertificateFileInFolder -Path $sWorkingDir)
        if ($aRootFiles.Count -gt 0) {
            $aFolders += [pscustomobject]@{ Name = "(working folder)"; Files = $aRootFiles.Count; Path = $sWorkingDir; Recurse = $false }
        }
        foreach ($oDir in (Get-ChildItem -LiteralPath $sWorkingDir -Directory -ErrorAction SilentlyContinue | Sort-Object -Property Name)) {
            $iCount = @(Get-CertificateFileInFolder -Path $oDir.FullName -Recurse).Count
            if ($iCount -gt 0) {
                $aFolders += [pscustomobject]@{ Name = $oDir.Name; Files = $iCount; Path = $oDir.FullName; Recurse = $true }
            }
        }
        $oFolderSel = Select-CLIDialogObjectInArray -Objects $aFolders `
            -SelectedColumns @(@{ l = "Name"; e = { $_.Name } }, @{ l = "Files"; e = { $_.Files } }) `
            -SelectHeaderMessage "Which certificate do you want to view?" `
            -EmptyArrayMessage "No certificate file in the working folders - use 'Other source'" `
            -OtherMenuItems @(
                New-CLIDialogButton -Other -Text "&Other source" -Object { return "Other" }
                New-CLIDialogButton -Text "&Back" -Back
                New-CLIDialogButton -Text "&Exit" -Exit
            ) `
            -FooterMessage "" -SeparatorColor $cSep -HeaderTextInSeparator -Space -DontShowPageNumberWhenOnlyOnePage
        if (Test-DialogAction $oFolderSel -Action "Exit") { return $oFolderSel }

        if (Test-DialogAction $oFolderSel -Action "Other") {
            $oInput = Read-CLIDialogValidatedValue `
                -Header "Enter a certificate file path, an HTTPS URL, a host[:port] (HTTPS, else SQL Server) or a SQL Server instance (server\instance)" `
                -PropertyName "Path / URL / Host" `
                -ValidationMethod { param($v) return ($v.Trim().Length -gt 0) } `
                -ErrorMessage "Value cannot be empty" `
                -AllowBack
            if (Test-DialogAction $oInput) { continue }
            $sSource = if ($oInput.PSTypeNames -and $oInput.PSTypeNames[0] -eq "DialogResult.Value") { $oInput.Value } else { [string]$oInput }
            $oResult = Show-CertificateSource_CLI -Source $sSource -OpenSSLPath $OpenSSLPath
            if (Test-DialogAction $oResult -Action "Exit") { return $oResult }
            continue
        }
        if (Test-DialogAction $oFolderSel) { return }
        $oFolder = $oFolderSel.Value

        # 2. Certificate files of the folder (opened directly when there is only one)
        while ($true) {
            $aFiles = @(Get-CertificateFileInFolder -Path $oFolder.Path -Recurse:$oFolder.Recurse | Sort-Object -Property FullName | ForEach-Object {
                [pscustomobject]@{
                    File     = $_.FullName.Substring($oFolder.Path.TrimEnd("\").Length + 1)
                    Modified = $_.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
                    FullName = $_.FullName
                }
            })
            if ($aFiles.Count -eq 0) { break }
            $sFile = if ($aFiles.Count -eq 1) {
                $aFiles[0].FullName
            } else {
                $oFileSel = Select-CLIDialogObjectInArray -Objects $aFiles `
                    -SelectedColumns @(@{ l = "File"; e = { $_.File } }, @{ l = "Modified"; e = { $_.Modified } }) `
                    -SelectHeaderMessage "Certificate files in $($oFolder.Name)" `
                    -OtherMenuItems @(
                        New-CLIDialogButton -Text "&Back" -Back
                        New-CLIDialogButton -Text "&Exit" -Exit
                    ) `
                    -FooterMessage "" -SeparatorColor $cSep -HeaderTextInSeparator -Space -DontShowPageNumberWhenOnlyOnePage
                if (Test-DialogAction $oFileSel -Action "Exit") { return $oFileSel }
                if (Test-DialogAction $oFileSel) { break }
                $oFileSel.Value.FullName
            }
            $oResult = Show-CertificateSource_CLI -Source $sFile -OpenSSLPath $OpenSSLPath
            if (Test-DialogAction $oResult -Action "Exit") { return $oResult }
            if ($aFiles.Count -eq 1) { break }
        }
    }
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
        New-MenuItem -Text "&Create PFX" -Content { New-PFX_CLI -OpenSSLPath $OpenSSLPath | Out-Null }
    ) -OtherMenuItems $aOtherMenuItems -SeparatorColor Blue
    New-MenuItem -Text "&View a certificate" -Content { Show-Certificate_CLI -OpenSSLPath $OpenSSLPath }
    New-MenuItem -Text "E&xport / Convert certificate" -Content { Convert-Certificate_CLI -OpenSSLPath $OpenSSLPath | Out-Null }
    New-MenuItem -Text "Certificates expiring soon" -Content { Show-ExpiringCertificates_CLI }
    New-Menu -Text "Change the certificate of an application se&rver" -Content @(
        New-MenuItem -Text "&RDS server" -Content { Set-RDSCertificate_CLI | Out-Null }
        New-MenuItem -Text "&SQL Server" -Content { Set-MSSqlCertificate_CLI }
        New-MenuItem -Text "&NetScaler ADC" -Content { Show-NetScalerCertificateCheck_CLI }
    ) -OtherMenuItems $aOtherMenuItems -SeparatorColor Blue
    New-MenuItem -Text "&Settings" -Content { Edit-ScriptConfig }
) -OtherMenuItems $mExit -SeparatorColor Blue

Invoke-Menu -Menu $Menu
