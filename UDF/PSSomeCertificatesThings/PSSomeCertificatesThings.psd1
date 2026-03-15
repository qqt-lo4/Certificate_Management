@{
    # Module manifest for PSSomeCertificatesThings

    # Script module associated with this manifest
    RootModule        = 'PSSomeCertificatesThings.psm1'

    # Version number of this module
    ModuleVersion     = '1.0.0'

    # ID used to uniquely identify this module
    GUID              = '7b3e52d1-4a96-4f08-b1c3-9d8e2a7f6c45'

    # Author of this module
    Author            = 'Loïc Ade'

    # Description of the functionality provided by this module
    Description       = 'Certificate management utilities: PKI and CA operations, CSR creation and signing, CRL retrieval, and OpenSSL helpers.'

    # Minimum version of PowerShell required by this module
    PowerShellVersion = '5.1'

    # Functions to export from this module
    FunctionsToExport = '*'

    # Cmdlets to export from this module
    CmdletsToExport   = @()

    # Variables to export from this module
    VariablesToExport  = @()

    # Aliases to export from this module
    AliasesToExport    = @()

    # Private data to pass to the module specified in RootModule
    PrivateData       = @{
        PSData = @{
            Tags       = @('Certificate', 'PKI', 'CSR', 'CRL', 'OpenSSL', 'X509')
            ProjectUri = ''
        }
    }
}
