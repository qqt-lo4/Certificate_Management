@{
    # Module manifest for PSSomeRDSThings

    # Script module associated with this manifest
    RootModule        = 'PSSomeRDSThings.psm1'

    # Version number of this module
    ModuleVersion     = '1.0.0'

    # ID used to uniquely identify this module
    GUID              = 'a4f2b1c8-9d6e-4a3b-bf75-2e8c1d9a7b34'

    # Author of this module
    Author            = 'Loïc Ade'

    # Description of the functionality provided by this module
    Description       = 'Microsoft Remote Desktop Services helpers: certificate discovery and deployment on Broker and Standalone deployments.'

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
            Tags       = @('RDS', 'RemoteDesktop', 'Certificate', 'TerminalServices')
            ProjectUri = ''
        }
    }
}
