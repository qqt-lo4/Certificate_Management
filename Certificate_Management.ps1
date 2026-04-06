Param(
    [string]$InputDir,
    [string]$WorkingDir
)

$iModulesCount = 7
$i = 0

#region Include
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
Write-Progress -Activity "Loading script modules" -Status "PSSomeNetworkThings" -PercentComplete (($($i++; $i) / $iModulesCount) * 100)
Import-Module $PSScriptRoot\UDF\PSSomeNetworkThings -Force
Write-Progress -Activity "Loading script modules" -Status "Loading end" -PercentComplete 100 -Completed
#endregion Include

#region script info
#scriptVersion=2.2
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
    $sWorkingDir = Get-ScriptDir -WorkingDir
    $sRealFolderName = $sFriendlyName
    $sFinalFolderName = $sWorkingDir + "\" + $sFriendlyName
    if (Test-Path ($sFinalFolderName)) {
        $sRealFolderName = $sFriendlyName + "_" + (Get-Date -Format "yyyyMMdd-HHmmss")
        $sFinalFolderName = $sWorkingDir + "\" + $sRealFolderName
    }
    New-Item -Path $sFinalFolderName -ItemType Directory | Out-Null
    $sKeyFileName = $sFinalFolderName + "\" + $sFriendlyName + ".key"
    $sCSRFileName = $sFinalFolderName + "\" + $sFriendlyName + ".req"
    $sConfigFileName = $sFinalFolderName + "\" + $sFriendlyName + ".inf"
    $hResult = @{
        SettingsInfPath = $sConfigFileName
        KeyOutPath = $sKeyFileName
        CSROutPath = $sCSRFileName
        FriendlyName = $sFriendlyName
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
            $hProperties = [ordered]@{
                IP = @{Regex = Get-IPRegex -FullLine; IgnoreOtherRegex = $true}
                DNS = @{Regex = Get-DNSRegex -FullLine -AllowWildcard}
            }
            $sReadArrayHeader = "Please specify DNS and IP subject alternative names.`nPlease enter a list of items, a new line per item. Finish the list by entering an empty item:"
            $hResult = Read-Array -Header $sReadArrayHeader -GroupByProperties $hProperties
            return $hResult
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
                $hSANs = Read-SANIPandDNS
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

function Read-CSR {
    Param(
        [switch]$ItemsMode
    )
    $sbCertificateObject = if ($ItemsMode) {
        {
            param($result)
            $sFreeStringRegex = "^$|^[0-9a-zA-Zéèàùêëîï _.-]+$"
            $hPrevious = $result.CertificateObject
            $hCertProps = [ordered]@{
                CommonName = @{regex = "^[0-9a-zA-Z ._*-]+$"; Text = $hPrevious.CommonName}
                Organisation = @{regex = $sFreeStringRegex; Text = $hPrevious.Organisation}
                OrganisationalUnit = @{regex = $sFreeStringRegex; Text = $hPrevious.OrganisationalUnit}
                Locality = @{regex = $sFreeStringRegex; Text = $hPrevious.Locality}
                State = @{regex = $sFreeStringRegex; Text = $hPrevious.State}
                CountryCode = @{regex = "^$|^..$"; Text = $hPrevious.CountryCode}
            }
            return Read-CLIDialogHashtable -Properties $hCertProps -AllowBack
        }
    } else {
        {
            param($result)
            $sPreviousDN = if ($result.CertificateObject) { $result.CertificateObject.Subject } else { "" }
            $oResult = Read-CLIDialogDN -Header "Please enter certificate object as DN format" -AllowBack -DefaultValue $sPreviousDN
            if ($null -ne $oResult -and $oResult.PSTypeNames -and $oResult.PSTypeNames[0] -eq "DialogResult.Action.Back") {
                return $oResult
            }
            return [ordered]@{Subject = $oResult}
        }
    }
    $steps = @(
        New-CLIDialogWizardStep -PropertyName "CertificateObject" -ScriptBlock $sbCertificateObject
        New-CLIDialogWizardStep -PropertyName "SAN" -ScriptBlock {
            param($result)
            $hPreviousSAN = if ($result.SAN -and ($result.SAN.SANdns -or $result.SAN.SANipaddress)) { $result.SAN } else { $null }
            return Read-SAN -CommonName $result.CertificateObject.CommonName -AskForValidation -AllowBack -PreviousValues $hPreviousSAN
        }
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
            $sPreviousName = if ($result.FileNames) { $result.FileNames.FriendlyName } else { "" }
            return Read-FileNames -DefaultFriendlyName $sPreviousName -AllowBack
        }
    )

    $oWizardResult = Invoke-CLIDialogWizard -Steps $steps

    # Handle Back/Exit
    if ($oWizardResult.PSTypeNames -and $oWizardResult.PSTypeNames[0] -like "DialogResult.Action.*") {
        return $oWizardResult
    }

    # Build the CSR hashtable from wizard results
    $hCSR = @{}
    $hCSR += $oWizardResult.CertificateObject
    $hCSR += $oWizardResult.SAN
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
        [switch]$ItemsMode
    )
    $oCSR = Read-CSR -ItemsMode:$ItemsMode
    if ($oCSR.PSObject.TypeNames[0] -eq "DialogResult.Action.Back") {
        return $oCSR
    }
    $hCSR = $oCSR.CSR
    $hMoreInfo = $oCSR.MoreInfo
    $hMoreInfo.Add("FolderName", $hCSR.FolderName)
    $hMoreInfo.Add("FriendlyName", $hCSR.FriendlyName)
    $hCSR.Remove("FolderName")
    $hCSR.Remove("FriendlyName")
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
        [string]$Message
    )
    $sWorkingDir = (Get-ScriptDir -WorkingDir)
    $oFolder = Select-CLIFileFromFolder -Path $sWorkingDir -Filter "*" -ColumnName "Name" -SeparatorColor Blue -SelectHeaderMessage $Message
    return $oFolder.Value.FullName
}

# function Get-PKICSRFolder {
#     Param(
#         [parameter(Mandatory, Position = 0)]
#         [string]$PKIServer
#     )
#     $sDefaultFolder = $ScriptConfig.PKICSRFolder.default
#     $sPKICSRFolder = $ScriptConfig.PKICSRFolder[$PKIServer]
#     if ($sPKICSRFolder) {
#         return $sPKICSRFolder
#     } else {
#         return $sDefaultFolder
#     }
# }

function Send-CSRToCA_CLI {
    Param(
        [string]$CertFolder,
        [object]$CSRConfig,
        [object]$CSRMoreInfo
    )
    $sCertFolder = if ($CertFolder) {
        $CertFolder   
    } else {
        Select-CertFolder -Message "Which CSR do you want to send to CA?"
    }
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
        Select-CertFolder -Message "Which certificate do you want to issue?"
    }
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
        Select-CertFolder -Message "Which certificate do you want to retreive from PKI server?"
    }
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
    $sCertName = if ($oCertInfo -and $oCertInfo.MoreInfo.FriendlyName) {
        $oCertInfo.MoreInfo.FriendlyName
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
        Select-CertFolder -Message "For which certificate do you want to build a PFX?"
    }
    $oCertInfo = Get-CertInfo -CertFolder $sCertFolder
    $sCertName = if ($oCertInfo -and $oCertInfo.MoreInfo.FriendlyName) {
        $oCertInfo.MoreInfo.FriendlyName
    } else {
        $sCertFolderName = $sCertFolder.Substring($sCertFolder.LastIndexOf("\") + 1)
        Get-CertificateNameFromFolder -FolderName $sCertFolderName
    }
    $sKeyFile = $sCertFolder + "\" + $sCertName + ".key"
    if (-not (Test-Path $sKeyFile -PathType Leaf)) {
        Write-Error "Private key file not found: $sKeyFile"
        return
    }

    $sP7BFile = $sCertFolder + "\" + $sCertName + ".p7b"
    $sOutPFXFile = $sCertFolder + "\" + $sCertName + ".pfx"

    $hMergeOptions = @{
        PrivateKey = $sKeyFile
        OutPFXFile = $sOutPFXFile
        OpenSSLPath = $OpenSSLPath
        FriendlyName = if ($oCertInfo -and $oCertInfo.MoreInfo.FriendlyName) { $oCertInfo.MoreInfo.FriendlyName } else { $sCertName }
    }

    if (Test-Path $sP7BFile -PathType Leaf) {
        # PKI mode: P7B certificate chain available
        $sCEROut = $sCertFolder + "\" + $sCertName + ".p7b.cer"
        Convert-P7BToCer -P7bPath $sP7BFile -OutCerFile $sCEROut -OpenSSLPath $OpenSSLPath
        $hMergeOptions.Cert = $sCEROut
    } else {
        # Public CA mode: separate certificate files (final, intermediate, root)
        $aCerFiles = @(Get-ChildItem -Path $sCertFolder -Include "*.cer", "*.crt" -File | Where-Object { $_.Name -notlike "*.p7b.cer" })
        Write-Host "No P7B found. Please specify the certificate files." -ForegroundColor Yellow
        Write-Host "Available files in folder:" -ForegroundColor Yellow
        foreach ($f in $aCerFiles) { Write-Host "  $($f.Name)" }
        Write-Host ""
        $hCertFiles = [ordered]@{
            "Certificate" = @{ Text = if ($aCerFiles.Count -ge 1) { $aCerFiles[0].FullName } else { "" } }
            "Intermediate CA" = @{ Text = if ($aCerFiles.Count -ge 2) { $aCerFiles[1].FullName } else { "" } }
            "Root CA" = @{ Text = if ($aCerFiles.Count -ge 3) { $aCerFiles[2].FullName } else { "" } }
        }
        $oResult = Read-CLIDialogHashtable -Properties $hCertFiles -Header "Certificate files for PFX generation" -AllowCancel
        if ($null -eq $oResult) { return }
        $hMergeOptions.Cert = $oResult.Certificate
        if ($oResult."Intermediate CA" -ne "") {
            $hMergeOptions.IntermediateCA = $oResult."Intermediate CA"
        }
        if ($oResult."Root CA" -ne "") {
            $hMergeOptions.RootCA = $oResult."Root CA"
        }
    }

    $ssKeyPassord = if ($PrivateKeyPassword) {
        $PrivateKeyPassword
    } else {
        Read-Host -AsSecureString -Prompt "Please enter private key password"
    }
    $sWindowsPFX = Invoke-YesNoCLIDialog -YN -Message "Will this PFX be used in the Windows certificate store?"
    $hMergeOptions.PFXPassword = $ssKeyPassord
    $hMergeOptions.KeyPassword = $ssKeyPassord
    $hMergeOptions.WindowsPFX = ($sWindowsPFX -eq "Yes")

    Merge-OpenSSLPFX @hMergeOptions
    if (Test-Path $sOutPFXFile) {
        Write-Host "PFX generated successfully" -ForegroundColor Green
        Write-Host ""
    } else {
        Write-Host "PFX generation failed" -ForegroundColor Red
        Write-Host ""
    }
}

function New-PKISignedCertAndPFX_CLI {
    Param(
        [string]$OpenSSLPath,
        [switch]$ItemsMode
    )
    $oCSR = New-CSR_CLI -OpenSSLPath $OpenSSLPath -ItemsMode:$ItemsMode
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
    ) -OtherMenuItems $aOtherMenuItems -SeparatorColor Blue
    New-Menu -Text "&Advanced certificate generation" -Content @(
        New-MenuItem -Text "New Certificate Request (items)" -Content { New-CSR_CLI -OpenSSLPath $OpenSSLPath -ItemsMode | Out-Null }
        New-MenuItem -Text "New Certificate Request (DN)" -Content { New-CSR_CLI -OpenSSLPath $OpenSSLPath | Out-Null }
        New-MenuItem -Text "Send CSR to CA" -Content { Send-CSRToCA_CLI | Out-Null }
        New-MenuItem -Text "Issue pending certificate request" -Content { Invoke-IssueCSR_CLI | Out-Null }
        New-MenuItem -Text "Get issued certificate" -Content { Get-IssuedCertificate_CLI | Out-Null }
        New-MenuItem -Text "Create PFX" -Content { New-PFX_CLI -OpenSSLPath $OpenSSLPath }    
    ) -OtherMenuItems $aOtherMenuItems -SeparatorColor Blue
    New-MenuItem -Text "&Settings" -Content { Edit-ScriptConfig }
) -OtherMenuItems $mExit -SeparatorColor Blue

Invoke-Menu -Menu $Menu
