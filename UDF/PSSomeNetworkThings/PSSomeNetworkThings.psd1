@{
    # Module manifest for PSSomeNetworkThings

    # Script module associated with this manifest
    RootModule        = 'PSSomeNetworkThings.psm1'

    # Version number of this module
    ModuleVersion     = '1.0.0'

    # ID used to uniquely identify this module
    GUID              = '391eb4de-6052-4ae1-880f-14dd898eae0c'

    # Author of this module
    Author            = 'Loïc Ade'

    # Description of the functionality provided by this module
    Description       = 'Network functions (Create objets with features from string, get NIC info, proxy, test strings, ...)'

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
            Tags       = @('Network', 'ipcalc', 'NIC', 'whois', 'RFC1918', 'oui')
            ProjectUri = ''
        }
    }
}
