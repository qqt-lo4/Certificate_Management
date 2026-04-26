function Test-CertificateIsParent {
    <#
    .SYNOPSIS
        Tests whether one X.509 certificate is the issuing parent of another

    .DESCRIPTION
        Decides whether the Parent certificate issued the Child certificate. The decision
        is based on the AuthorityKeyIdentifier of the child compared against the
        SubjectKeyIdentifier of the parent (the X.509 way of chaining); when either
        extension is missing on the relevant certificate, the function falls back to a
        Subject == Issuer DN comparison.

        This function does not verify the cryptographic signature: it only answers the
        structural question "is Parent the cert that signed Child according to identifiers?".
        Two distinct certificates with identical names and matching identifiers (a renewed
        intermediate, for instance) cannot be distinguished without signature verification.

    .PARAMETER Parent
        The candidate parent certificate.

    .PARAMETER Child
        The certificate whose parent is being tested.

    .OUTPUTS
        [bool].

    .EXAMPLE
        Test-CertificateIsParent -Parent $intermediate -Child $leaf

    .EXAMPLE
        # Find the immediate parent of a cert in a candidate set:
        $parent = $candidates | Where-Object { Test-CertificateIsParent -Parent $_ -Child $cert } | Select-Object -First 1

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-04-26 - Loïc Ade
            - Initial release
            - SKI / AKI matching with DN fallback
            - Always returns $false when comparing a certificate to itself (by Thumbprint)
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    Param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Parent,
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Child
    )
    if ($Parent.Thumbprint -eq $Child.Thumbprint) { return $false }

    $sChildAKI  = Get-CertificateAKI -Certificate $Child
    $sParentSKI = Get-CertificateSKI -Certificate $Parent

    if ($sChildAKI -and $sParentSKI) {
        return $sChildAKI -eq $sParentSKI
    }
    return $Parent.Subject -eq $Child.Issuer
}
