@{
    # Module manifest for PSSomeAuthThings

    # Script module associated with this manifest
    RootModule        = 'PSSomeAuthThings.psm1'

    # Version number of this module
    ModuleVersion     = '1.0.0'

    # ID used to uniquely identify this module
    GUID              = '2e8c47b3-d195-4a6f-8b02-c3f9a17d5e84'

    # Author of this module
    Author            = 'Loïc Ade'

    # Description of the functionality provided by this module
    Description       = 'Authentication and credential management: PSCredential helpers, password policy validation, and Windows Credential Manager integration.'

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
            Tags       = @('Authentication', 'Credential', 'Password', 'CredentialManager', 'Security')
            ProjectUri = ''
        }
    }
}