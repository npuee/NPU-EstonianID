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

    .EXAMPLE
    Get-EstEIDCertificate -ID '38001085718'

    .EXAMPLE
    # Use cached certificate if available
    Get-EstEIDCertificate -ID '38001085718' -UseCache

    .EXAMPLE
    # Pipeline query
    '38001085718', '60001019906' | Get-EstEIDCertificate
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]
        [ValidatePattern('^\d{11}$')]
        [Alias('EstonianID', 'PersonalCode', 'Isikukood')]
        [string]$ID,

        [Parameter()]
        [switch]$UseCache,

        [Parameter()]
        [switch]$Raw
    )

    process {
        $certByteList = $null
        try {
            $certByteList = Get-LdapCertificatesInternal -ID $ID -UseCache:$UseCache
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
                    Write-Output $cert
                }
                catch {
                    Write-Warning "Failed to parse certificate bytes for ID '$ID': $($_.Exception.Message)"
                }
            }
        }
    }
}
