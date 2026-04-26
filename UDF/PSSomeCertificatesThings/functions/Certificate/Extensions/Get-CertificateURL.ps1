function Get-CertificateURL {
    <#
    .SYNOPSIS
        Retrieves URLs from a certificate's extensions

    .DESCRIPTION
        Extracts Certificate Distribution Point (CDP), Authority Information Access (AIA),
        and Online Certificate Status Protocol (OCSP) URLs from an X509Certificate2 object.
        Uses P/Invoke to call CryptGetObjectUrl from cryptnet.dll.

    .PARAMETER Cert
        The X509Certificate2 object to extract URLs from.

    .OUTPUTS
        [PSCustomObject]. Object with CDP (array), AIA (array), and OCSP (array) properties containing URLs.

    .EXAMPLE
        $cert = Get-Item Cert:\LocalMachine\My\THUMBPRINT
        $urls = Get-CertificateURL -Cert $cert
        $urls.CDP
        $urls.AIA
        $urls.OCSP

    .EXAMPLE
        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("C:\Certs\cert.cer")
        Get-CertificateURL -Cert $cert

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )
    $signature = @"
    [DllImport("cryptnet.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool CryptGetObjectUrl(
        int pszUrlOid,
        IntPtr pvPara,
        int dwFlags,
        byte[] pUrlArray,
        ref int pcbUrlArray,
        IntPtr pUrlInfo,
        ref int pcbUrlInfo,
        int pvReserved
    );
"@
    Add-Type -MemberDefinition $signature -Namespace PKI -Name Cryptnet

    # create synthetic object to store resulting URLs
    $URLs = New-Object psobject -Property @{
        CDP = $null;
        AIA = $null;
        OCSP = $null;
    }
    $pvPara = $Cert.Handle
    # process only if Handle is not zero.
    if (!$Cert.Handle.Equals([IntPtr]::Zero)) {
        # loop over each URL type: AIA, CDP and OCSP
        foreach ($id in 1,2,13) {
            # initialize reference variables
            $pcbUrlArray = 0
            $pcbUrlInfo = 0
            # call CryptGetObjectUrl to get required buffer size. The function returns True if succeeds and False otherwise
            if ([PKI.Cryptnet]::CryptGetObjectUrl($id,$pvPara,2,$null,[ref]$pcbUrlArray,[IntPtr]::Zero,[ref]$pcbUrlInfo,$null)) {
                # create buffers to receive the data
                $pUrlArray = New-Object byte[] -ArgumentList $pcbUrlArray
                $pUrlInfo = [Runtime.InteropServices.Marshal]::AllocHGlobal($pcbUrlInfo)
                # call CryptGetObjectUrl to receive decoded URLs to the buffer.
                [void][PKI.Cryptnet]::CryptGetObjectUrl($id,$pvPara,2,$pUrlArray,[ref]$pcbUrlArray,$pUrlInfo,[ref]$pcbUrlInfo,$null)
                # convert byte array to a single string
                $URL = ConvertTo-DERString $pUrlArray
                # parse unicode string to remove extra insertions
                switch ($id) {
                    1 {
                        $URL = $URL.Split("`0",[StringSplitOptions]::RemoveEmptyEntries)
                        $URLs.AIA = $URL[4..($URL.Length - 1)]
                    }
                    2 {
                        $URL = $URL.Split("`0",[StringSplitOptions]::RemoveEmptyEntries)
                        $URLs.CDP = $URL[4..($URL.Length - 1)]
                    }
                    13 {
                        $URL = $URL -split "ocsp:"
                        $URLs.OCSP = $URL[1..($URL.Length - 1)] | %{$_ -replace [char]0}
                    }
                }
                # free unmanaged buffer
                [void][Runtime.InteropServices.Marshal]::FreeHGlobal($pUrlInfo)
            } else {Write-Warning "No Urls"}
        }
        $URLs
    }
}
