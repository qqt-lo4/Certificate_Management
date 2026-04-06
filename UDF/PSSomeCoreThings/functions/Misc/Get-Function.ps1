function Get-Function {
    <#
    .SYNOPSIS
        Retrieves a function, alias, or command object by name

    .DESCRIPTION
        Looks up a command by name, checking aliases first (resolving to the target),
        then functions, then general commands.

    .PARAMETER Name
        The function, alias, or command name to look up.

    .OUTPUTS
        [FunctionInfo], [AliasInfo], [CommandInfo], or $null.

    .EXAMPLE
        $func = Get-Function "Write-LogInfo"

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>

    Param(
        [Parameter(Mandatory, Position = 0)]
        [ValidatePattern("[a-zA-Z0-9_-]")]
        [string]$Name
    )
    # Old version (doesn't work across module scope boundaries):
    # $oAlias = Get-Alias $Name -ErrorAction SilentlyContinue
    # if ($oAlias) {
    #     if ($null -ne $oAlias.ResolvedCommand) {
    #         return $oAlias.ResolvedCommand
    #     } else {
    #         return $null
    #     }
    # }
    # $oFunc = Get-Item Function:\$Name -ErrorAction SilentlyContinue
    # if ($oFunc) {
    #     return $oFunc
    # }
    # $oCommand = Get-Command $Name -ErrorAction SilentlyContinue
    # if ($oCommand) {
    #     return $oCommand
    # }
    # return $null

    $oCommand = Get-Command $Name -ErrorAction SilentlyContinue
    if ($oCommand) {
        if ($oCommand.CommandType -eq 'Alias') {
            return $oCommand.ResolvedCommand
        }
        return $oCommand
    }
    return $null
}
