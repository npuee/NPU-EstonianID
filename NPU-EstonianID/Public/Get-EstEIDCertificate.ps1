function Get-EstEIDCertificate {
    <#
    .SYNOPSIS
    Retrieves the ID card and Digi-ID authentication certificates of an Estonian personal code from the eID LDAP directories.

    .DESCRIPTION
    A person has at most one ID card, issued either by SK ID Solutions (ESTEID2018) or by Zetes (ESTEID2025),
    and may also have an SK Digi-ID (the blue card, being phased out).

    SK ID Solutions (esteid.ldap.sk.ee) is searched first. If it has the person's ID card, Zetes
    (ldap.eidpki.ee) is not searched; otherwise (no SK certificate, or only a Digi-ID) Zetes is searched too.
    Mobile-ID, e-resident and residence permit certificates are ignored. Certificates are only returned if they
    are currently valid and issued to the personal code.

    If a directory that has to be searched cannot be reached, an error is written and nothing is returned,
    so callers never act on a partial answer.

    Returns in-memory X509Certificate2 objects directly without saving temporary files to disk.

    .PARAMETER ID
    11-digit Estonian personal identification code (isikukood). Accepts pipeline input.

    .PARAMETER CardType
    Which certificates to return: IdCard, DigiId or both (default). Protect-Cdoc uses IdCard only.

    .PARAMETER UseCache
    Enables local disk and in-memory caching to avoid rate limits during bulk queries. Disabled by default (live queries).

    .PARAMETER Raw
    Returns raw certificate bytes ([byte[]]) instead of X509Certificate2 objects.

    .PARAMETER OutFolder
    Saves each certificate as a DER-encoded 'cert_<ID>_<SerialNumber>.cer' file in this folder (created if missing)
    and returns the FileInfo objects of the saved files instead of certificate objects.

    .EXAMPLE
    Get-EstEIDCertificate -ID '38001085718'

    .EXAMPLE
    # Only the ID card certificate, with the card type shown
    Get-EstEIDCertificate -ID '38001085718' -CardType IdCard | Select-Object CardType, Subject, Issuer, NotAfter

    .EXAMPLE
    # Use cached certificate if available
    Get-EstEIDCertificate -ID '38001085718' -UseCache

    .EXAMPLE
    # Pipeline query
    '38001085718', '60001019906' | Get-EstEIDCertificate

    .EXAMPLE
    # Save the certificates to files
    Get-EstEIDCertificate -ID '38001085718' -OutFolder C:\Certs

    .OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2 by default, with a CardType property (IdCard or DigiId);
    System.Byte[] with -Raw; System.IO.FileInfo (the saved .cer files) with -OutFolder.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Object')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidatePattern('^\d{11}$')]
        [Alias('EstonianID', 'PersonalCode', 'Isikukood')]
        [string]$ID,

        [Parameter()]
        [ValidateSet('IdCard', 'DigiId')]
        [string[]]$CardType = @('IdCard', 'DigiId'),

        [Parameter()]
        [switch]$UseCache,

        [Parameter(ParameterSetName = 'Raw')]
        [switch]$Raw,

        [Parameter(Mandatory = $true, ParameterSetName = 'Save')]
        [string]$OutFolder
    )

    process {
        try {
            $entries = @(_getLdapCertificates -ID $ID -UseCache:$UseCache)
        }
        catch {
            Write-Error -Message $_.Exception.Message `
                        -ErrorId 'EstEIDLookupIncomplete' `
                        -Category ConnectionError `
                        -TargetObject $ID
            return
        }

        $entries = @($entries | Where-Object { $CardType -contains $_.CardType })
        if ($entries.Count -eq 0) {
            Write-Verbose "No $($CardType -join '/') certificates found for ID '$ID'."
            return
        }

        foreach ($entry in $entries) {
            if ($Raw) {
                Write-Output (, $entry.CertBytes)
                continue
            }
            try {
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($entry.CertBytes)
            }
            catch {
                Write-Warning "Failed to parse certificate bytes for ID '$ID': $($_.Exception.Message)"
                continue
            }
            if ($PSCmdlet.ParameterSetName -eq 'Save') {
                $folder = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($OutFolder)
                if (-not (Test-Path -LiteralPath $folder -PathType Container)) {
                    $null = New-Item -ItemType Directory -Path $folder -Force
                }
                $certFile = Join-Path -Path $folder -ChildPath "cert_${ID}_$($cert.SerialNumber).cer"
                [System.IO.File]::WriteAllBytes($certFile, $cert.RawData)
                Get-Item -LiteralPath $certFile
            }
            else {
                $cert | Add-Member -NotePropertyName CardType -NotePropertyValue $entry.CardType -PassThru
            }
        }
    }
}
