@{
    # Module manifest for PSSomeMSSqlThings

    # Script module associated with this manifest
    RootModule        = 'PSSomeMSSqlThings.psm1'

    # Version number of this module
    ModuleVersion     = '1.0.0'

    # ID used to uniquely identify this module
    GUID              = '550c904e-6c19-4cfc-83bb-81cd7dd7b797'

    # Author of this module
    Author            = 'Loïc Ade'

    # Description of the functionality provided by this module
    Description       = 'Microsoft SQL Server helpers: instance discovery and TLS certificate renewal.'

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
            Tags       = @('SQLServer', 'MSSQL', 'Certificate', 'TLS')
            ProjectUri = ''
        }
    }
}
