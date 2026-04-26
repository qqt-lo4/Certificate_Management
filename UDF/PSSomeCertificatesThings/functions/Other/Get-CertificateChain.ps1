function Get-CertificateChain {
    <#
    .SYNOPSIS
        Reconstructs an ordered certification chain from an unordered set of certificate files

    .DESCRIPTION
        Loads every certificate found in the provided files (DER/PEM CER, CRT, or PKCS#7
        P7B), deduplicates them by Thumbprint, identifies the leaf (the certificate that
        is not the parent of any other certificate in the provided set) and walks parent
        links upward via Test-CertificateIsParent.

        When -IncludeOSStore is set, the candidate pool used for parent lookup is extended
        with the certificates found in the Windows certificate stores (CA, Root, AuthRoot,
        in both LocalMachine and CurrentUser scope). The leaf is still identified within
        the provided files only, so OS-store entries cannot accidentally outrank the
        user-supplied leaf.

        The returned array is ordered from leaf to root. The function throws when:
          - no certificate could be loaded
          - no leaf can be identified (every provided certificate is the parent of another:
            a loop or duplicates with conflicting identifiers)
          - the chain does not terminate with a self-signed certificate (Subject == Issuer):
            the caller is expected to feed the function a complete chain up to the root,
            possibly relying on -IncludeOSStore to fill in intermediates and roots.

    .PARAMETER CertificateFiles
        One or more paths to certificate files. Files containing multiple certificates
        (P7B bundles) are expanded transparently.

    .PARAMETER IncludeOSStore
        Extend the candidate pool with the certificates found in the Windows certificate
        stores (Cert:\LocalMachine\CA, Cert:\LocalMachine\Root, Cert:\LocalMachine\AuthRoot
        and the same three under CurrentUser). Useful when the caller only owns the leaf
        and expects the intermediates / root to be available system-wide.

    .OUTPUTS
        [System.Security.Cryptography.X509Certificates.X509Certificate2[]]. Ordered array
        from leaf (index 0) to root (last index).

    .EXAMPLE
        $chain = Get-CertificateChain -CertificateFiles (Get-ChildItem C:\dump\*.cer).FullName
        $chain[0].Subject              # leaf
        $chain[-1].Subject             # root

    .EXAMPLE
        # A single self-signed certificate is itself a complete chain of length 1:
        Get-CertificateChain -CertificateFiles 'C:\ca\selfsigned.cer'

    .EXAMPLE
        # Caller only has the leaf; intermediates and root come from the OS store:
        Get-CertificateChain -CertificateFiles 'C:\out\srv.cer' -IncludeOSStore

    .NOTES
        Author  : Loïc Ade
        Version : 1.0.0

        CHANGELOG:

        Version 1.0.0 - 2026-04-26 - Loïc Ade
            - Initial release
            - Loads CER/CRT/P7B inputs via X509Certificate2Collection.Import
            - Deduplicates by Thumbprint
            - Uses Test-CertificateIsParent for AKI/SKI matching with Subject/Issuer fallback
            - Throws when the chain does not terminate with a self-signed root
            - -IncludeOSStore extends the parent-lookup pool with certificates from
              Cert:\LocalMachine\{CA,Root,AuthRoot} and the same three under CurrentUser,
              while leaf detection still operates on the provided files only
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2[]])]
    Param(
        [Parameter(Mandatory)]
        [ValidateScript({
            foreach ($p in $_) {
                if (-not (Test-Path -Path $p -PathType Leaf)) { throw "Certificate file does not exist: $p" }
            }
            return $true
        })]
        [string[]]$CertificateFiles,
        [switch]$IncludeOSStore
    )

    # Provided certs (deduped by Thumbprint, insertion order preserved)
    $hProvided = [ordered]@{}
    foreach ($sFile in $CertificateFiles) {
        $oCol = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
        try {
            $oCol.Import($sFile)
        } catch {
            throw "Failed to read certificates from '$sFile': $_"
        }
        foreach ($oCert in $oCol) {
            if (-not $hProvided.Contains($oCert.Thumbprint)) {
                $hProvided[$oCert.Thumbprint] = $oCert
            }
        }
    }
    $aProvided = @($hProvided.Values)
    if ($aProvided.Count -eq 0) {
        throw "No certificates could be loaded from the provided files"
    }

    # Candidate pool used for parent lookup: provided + OS store (when requested)
    $hCandidates = [ordered]@{}
    foreach ($oCert in $aProvided) { $hCandidates[$oCert.Thumbprint] = $oCert }
    if ($IncludeOSStore) {
        foreach ($sPath in @(
            'Cert:\LocalMachine\CA', 'Cert:\LocalMachine\Root', 'Cert:\LocalMachine\AuthRoot',
            'Cert:\CurrentUser\CA',  'Cert:\CurrentUser\Root',  'Cert:\CurrentUser\AuthRoot'
        )) {
            if (Test-Path -LiteralPath $sPath) {
                foreach ($oCert in (Get-ChildItem -LiteralPath $sPath -ErrorAction SilentlyContinue)) {
                    if (-not $hCandidates.Contains($oCert.Thumbprint)) {
                        $hCandidates[$oCert.Thumbprint] = $oCert
                    }
                }
            }
        }
    }
    $aCandidates = @($hCandidates.Values)

    # Identify the leaf among the provided certs only (so OS store entries cannot win)
    $oLeaf = $null
    foreach ($oCert in $aProvided) {
        $bIsParent = $false
        foreach ($oOther in $aProvided) {
            if (Test-CertificateIsParent -Parent $oCert -Child $oOther) {
                $bIsParent = $true
                break
            }
        }
        if (-not $bIsParent) {
            $oLeaf = $oCert
            break
        }
    }
    if (-not $oLeaf) {
        throw "Could not identify a leaf certificate (chain has a loop?)"
    }

    # Walk parent links upward; require termination on a self-signed certificate
    $aChain = @($oLeaf)
    $oCurrent = $oLeaf
    $hVisited = @{ $oLeaf.Thumbprint = $true }
    while ($oCurrent.Subject -ne $oCurrent.Issuer) {
        $oParent = $aCandidates |
            Where-Object { -not $hVisited.Contains($_.Thumbprint) -and (Test-CertificateIsParent -Parent $_ -Child $oCurrent) } |
            Select-Object -First 1
        if (-not $oParent) {
            throw "Chain is missing the root: no parent found for '$($oCurrent.Subject)' and the chain is not terminated by a self-signed certificate."
        }
        $aChain += $oParent
        $hVisited[$oParent.Thumbprint] = $true
        $oCurrent = $oParent
    }

    return ,$aChain
}
