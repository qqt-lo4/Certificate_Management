function Expand-ComputerIPInfo {
    <#
    .SYNOPSIS
        Resolves and adds the IP address to an AD computer object

    .DESCRIPTION
        Performs a DNS A record lookup for the computer name and adds the resolved
        IP address to the object's AdditionalProperties if not already present.

    .PARAMETER Computer
        The AD computer object to enrich with IP information. Accepts pipeline input.

    .OUTPUTS
        None. The Computer object is modified in-place.

    .EXAMPLE
        $computer | Expand-ComputerIPInfo

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    Param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [object]$Computer
    )

    Begin {
        function Resolve-ComputerIP {
            Param(
                [Parameter(Mandatory, ValueFromPipeline, Position = 0)]
                [object]$Computer
            )
            return (Resolve-DnsName $Computer.name -Type A).IPAddress
        }
    }

    Process {
        if ($null -eq $Computer.IP) {
            $Computer.AdditionalProperties.IP = Resolve-ComputerIP $Computer
        }
    }
}
