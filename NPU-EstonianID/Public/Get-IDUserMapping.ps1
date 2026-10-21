function Get-IDUserMapping {
    <#
    .SYNOPSIS
    Queries Estonian eID LDAP directories or formats in-memory certificates into Active Directory altSecurityIdentities mappings.

    .DESCRIPTION
    Generates strong certificate name mappings (X509:<I>...<SR>...) required for Active Directory Smart Card authentication.
    Can resolve certificates by 11-digit personal code via LDAP (SK or Zetes) or directly from in-memory X509Certificate2 objects.

    .PARAMETER EstonianID
    11-digit Estonian personal identification code (isikukood). Accepts pipeline input.

    .PARAMETER Certificate
    In-memory X509Certificate2 object or certificate bytes to generate mapping for directly.

    .PARAMETER UseCache
    Enables local disk and in-memory caching to avoid rate limits during bulk queries. Disabled by default (live queries).

    .EXAMPLE
    Get-IDUserMapping -EstonianID '38001085718'

    .EXAMPLE
    $cert = Get-EstEIDCertificate -ID '60001019906'
    Get-IDUserMapping -Certificate $cert

    .EXAMPLE
    '38001085718', '60001019906' | Get-IDUserMapping
    #>
    [CmdletBinding(DefaultParameterSetName = 'Identity')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0, ParameterSetName = 'Identity')]
        [ValidatePattern('^\d{11}$')]
        [Alias('ID')]
        [string]$EstonianID,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0, ParameterSetName = 'Cert')]
        [Alias('Cert')]
        [object]$Certificate,

        [Parameter(ParameterSetName = 'Identity')]
        [switch]$UseCache
    )

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Cert') {
            $certObj = $Certificate
            if ($certObj -is [byte[]]) {
                $certObj = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$certObj)
            }
            if ($certObj -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                _Format-X509StrongNameMapping -Certificate $certObj
            }
            else {
                throw "Invalid certificate object type: $($Certificate.GetType().FullName)"
            }
            return
        }

        $certs = $null
        try {
            $certs = @(Get-EstEIDCertificate -ID $EstonianID -UseCache:$UseCache -ErrorAction Stop)
        }
        catch {
            $PSCmdlet.WriteError($_)
            return
        }
        $mappings = [System.Collections.Generic.List[string]]::new()

        foreach ($cert in $certs) {
            if ($cert) {
                $mapping = _Format-X509StrongNameMapping -Certificate $cert
                if ($mapping -and -not $mappings.Contains($mapping)) {
                    $mappings.Add($mapping)
                    Write-Output $mapping
                }
            }
        }
    }
}

