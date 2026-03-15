@{
    # Module manifest for PSSomeActiveDirectoryThings

    # Script module associated with this manifest
    RootModule        = 'PSSomeActiveDirectoryThings.psm1'

    # Version number of this module
    ModuleVersion     = '1.0.0'

    # ID used to uniquely identify this module
    GUID              = '9a2d74c3-5b18-4e6f-a307-8c1f5d923e60'

    # Author of this module
    Author            = 'Loïc Ade'

    # Description of the functionality provided by this module
    Description       = 'Active Directory management utilities: user, computer, group and object operations, domain and forest queries, LAPS, event log analysis, and CLI dialogs for AD object selection.'

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
            Tags       = @('ActiveDirectory', 'AD', 'LDAP', 'User', 'Computer', 'Group', 'LAPS', 'Domain', 'LAPS')
            ProjectUri = ''
        }
    }
}
