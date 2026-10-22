function Get-EstEIDCertificate {
    <#
    .SYNOPSIS
    Retrieves public X.509 authentication/encryption certificates from Estonian eID LDAP directories.

    .DESCRIPTION
    Queries both SK ID Solutions (esteid.ldap.sk.ee) and Thales / Zetes (ldap.eidpki.ee) directory services
    for authentication certificates belonging to the specified 11-digit Estonian personal code.
    Returns in-memory X509Certificate2 objects directly without saving temporary files to disk.

    .PARAMETER ID
    11-digit Estonian personal identification code (isikukood). Accepts pipeline input.

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
    # Use cached certificate if available
    Get-EstEIDCertificate -ID '38001085718' -UseCache

    .EXAMPLE
    # Pipeline query
    '38001085718', '60001019906' | Get-EstEIDCertificate

    .EXAMPLE
    # Save the certificates to files
    Get-EstEIDCertificate -ID '38001085718' -OutFolder C:\Certs
    .OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2 by default; System.Byte[] with -Raw; System.IO.FileInfo (the saved .cer files) with -OutFolder.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Object')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidatePattern('^\d{11}$')]
        [Alias('EstonianID', 'PersonalCode', 'Isikukood')]
        [string]$ID,

        [Parameter()]
        [switch]$UseCache,

        [Parameter(ParameterSetName = 'Raw')]
        [switch]$Raw,

        [Parameter(Mandatory = $true, ParameterSetName = 'Save')]
        [string]$OutFolder
    )

    process {
        $certByteList = $null
        try {
            $certByteList = _getLdapCertificates -ID $ID -UseCache:$UseCache
        }
        catch {
            Write-Error -Message $_.Exception.Message `
                        -ErrorId 'EstEIDLookupIncomplete' `
                        -Category ConnectionError `
                        -TargetObject $ID
            return
        }

        if (-not $certByteList -or $certByteList.Count -eq 0) {
            Write-Verbose "No certificates found for ID '$ID'."
            return
        }

        # Normalize certificate items, guarding against PowerShell pipeline unrolling
        $certItems = [System.Collections.Generic.List[byte[]]]::new()
        if ($certByteList -is [byte[]]) {
            $certItems.Add($certByteList)
        }
        elseif ($certByteList.Count -gt 0 -and $certByteList[0] -is [byte]) {
            $certItems.Add([byte[]]$certByteList)
        }
        else {
            foreach ($item in $certByteList) {
                if ($item -is [byte[]]) {
                    $certItems.Add($item)
                }
            }
        }

        foreach ($bytes in $certItems) {
            if ($Raw) {
                Write-Output $bytes
            }
            else {
                try {
                    $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)
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
                    Write-Output $cert
                }
            }
        }
    }
}
