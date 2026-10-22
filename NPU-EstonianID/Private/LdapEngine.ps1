#
# NPU-EstonianID - Common LDAP & Cache Engine
#

# LDAP directories (module settings; the tests point them at a closed local port)
$script:EstIDLdapURL = "esteid.ldap.sk.ee"
$script:EstIDLdapPort = 636
$script:EstIDLdapDN = "dc=ESTEID,c=EE"

$script:ThalesLdapURL = "ldap.eidpki.ee"
$script:ThalesLdapPort = 636
$script:ThalesLdapDN = "dc=ldap,dc=eidpki,dc=ee"

# Caching Configuration (Protects against Zetes 60 req/hr rate limits)
# Kept in the user profile, not %TEMP%: whoever can write the cache decides who Protect-Cdoc encrypts to,
# and for SYSTEM %TEMP% is C:\Windows\Temp, which every local user can write to.
$localAppData = [Environment]::GetFolderPath('LocalApplicationData')
$script:CacheFolder = if ($localAppData) { Join-Path -Path $localAppData -ChildPath 'NPU-EstonianID\CertCache' } else { $null }
$script:CacheTTLHours = 24
$script:MemoryCache = @{}

# Returns $null if the certificate is currently valid and issued to the personal code, otherwise the reason it is not.
function _getCertificateProblem {
    param(
        [byte[]]$CertBytes,
        [string]$ID
    )

    try {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($CertBytes)
    }
    catch {
        return "not a parseable certificate: $($_.Exception.Message)"
    }
    if ($cert.Subject -notmatch "(^|,\s*)SERIALNUMBER=PNOEE-$ID(\s*,|$)") {
        return "subject '$($cert.Subject)' does not belong to PNOEE-$ID"
    }
    $now = [DateTime]::Now
    if ($cert.NotBefore -gt $now -or $cert.NotAfter -lt $now) {
        return "certificate '$($cert.Subject)' is only valid from $($cert.NotBefore) to $($cert.NotAfter)"
    }
    return $null
}

function _getCachedCertificates {
    param([string]$ID)

    # 1. Check in-memory cache
    if ($script:MemoryCache.ContainsKey($ID)) {
        $entry = $script:MemoryCache[$ID]
        if ((([DateTime]::UtcNow) - $entry.Timestamp).TotalHours -lt $script:CacheTTLHours) {
            return , $entry.CertBytesList
        }
    }

    # 2. Check disk cache
    if (-not $script:CacheFolder) {
        return $null
    }
    $cacheFile = Join-Path -Path $script:CacheFolder -ChildPath "$ID.json"
    if (Test-Path -LiteralPath $cacheFile) {
        try {
            $data = Get-Content -LiteralPath $cacheFile -Raw | ConvertFrom-Json
            $timestamp = [DateTime]::Parse($data.Timestamp, [System.Globalization.CultureInfo]::InvariantCulture)
            if ((([DateTime]::UtcNow) - $timestamp).TotalHours -lt $script:CacheTTLHours) {
                $rawList = [System.Collections.Generic.List[byte[]]]::new()
                foreach ($b64 in $data.Base64Certs) {
                    $rawList.Add([Convert]::FromBase64String($b64))
                }
                $script:MemoryCache[$ID] = @{
                    Timestamp     = $timestamp
                    CertBytesList = $rawList.ToArray()
                }
                return , $rawList.ToArray()
            }
        } catch {
            Write-Verbose "Ignoring unreadable cache file '$cacheFile': $($_.Exception.Message)"
        }
    }
    return $null
}

function _setCachedCertificates {
    param(
        [string]$ID,
        [byte[][]]$CertBytesList
    )
    $now = [DateTime]::UtcNow
    # 1. Store in memory
    $script:MemoryCache[$ID] = @{
        Timestamp     = $now
        CertBytesList = $CertBytesList
    }

    # 2. Store on disk
    if (-not $script:CacheFolder) {
        return
    }
    try {
        if (-not (Test-Path -LiteralPath $script:CacheFolder)) {
            New-Item -ItemType Directory -Path $script:CacheFolder -Force | Out-Null
        }
        $cacheFile = Join-Path -Path $script:CacheFolder -ChildPath "$ID.json"
        $b64List = [System.Collections.Generic.List[string]]::new()
        foreach ($bytes in $CertBytesList) {
            $b64List.Add([Convert]::ToBase64String($bytes))
        }
        $obj = @{
            Timestamp   = $now.ToString("o")
            Base64Certs = $b64List.ToArray()
        }
        $json = $obj | ConvertTo-Json
        Set-Content -LiteralPath $cacheFile -Value $json -Encoding utf8
    } catch {
        Write-Verbose "Could not write the certificate cache for ID '$ID': $($_.Exception.Message)"
    }
}

function _getLdapCertificates {
    [CmdletBinding()]
    [OutputType([byte[][]])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '', Justification = '"return , $certArray" outputs the byte[][] as one object; the analyzer sees the Object[] wrapper.')]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ID,

        [Parameter()]
        [switch]$UseCache
    )

    if ($UseCache) {
        $cached = _getCachedCertificates -ID $ID
        if ($cached -and $cached.Count -gt 0) {
            $problems = @($(foreach ($bytes in $cached) { _getCertificateProblem -CertBytes $bytes -ID $ID }) | Where-Object { $_ })
            if ($problems.Count -eq 0) {
                Write-Verbose "Retrieved certificate(s) for ID '$ID' from cache."
                return $cached
            }
            Write-Warning "Ignoring cached certificate(s) for ID '$ID' and querying LDAP instead: $($problems -join '; ')"
            $script:MemoryCache.Remove($ID)
        }
    }

    $discoveredCerts = [System.Collections.Generic.List[byte[]]]::new()
    $IDCodeFilter = "(serialNumber=PNOEE-$ID)"
    $errors = [System.Collections.Generic.List[string]]::new()

    # 1. Search SK ID Solutions LDAP (esteid.ldap.sk.ee) - ESTEID2018
    $skUrl  = $script:EstIDLdapURL
    $skPort = $script:EstIDLdapPort
    $skDN   = $script:EstIDLdapDN

    $ldap = $null
    $ds   = $null
    try {
        $ldapdn = "LDAP://$skUrl`:$skPort/$skDN"
        $auth = [System.DirectoryServices.AuthenticationTypes]::Anonymous
        $ldap = New-Object System.DirectoryServices.DirectoryEntry($ldapdn, $null, $null, $auth)

        $ds = New-Object System.DirectoryServices.DirectorySearcher($ldap)
        $ds.Filter = $IDCodeFilter
        [void]$ds.PropertiesToLoad.Add("usercertificate;binary")

        $searchResults = $ds.FindAll()
        foreach ($result in $searchResults) {
            if ($result.Path -like "*ou=Authentication*" -and $result.Path -notlike "*o=Mobile-ID*") {
                if ($result.Properties['usercertificate;binary'].Count -gt 0) {
                    $rawVal = $result.Properties['usercertificate;binary'][0]
                    $byteCert = if ($rawVal -is [byte[]]) {
                        $rawVal
                    } else {
                        [Convert]::FromBase64String($rawVal.ToString())
                    }
                    if ($byteCert -and $byteCert.Length -gt 0) {
                        $discoveredCerts.Add($byteCert)
                    }
                }
            }
        }
    }
    catch {
        Write-Verbose "Could not query SK LDAP ($skUrl): $($_.Exception.Message)"
        $errors.Add("${skUrl}: $($_.Exception.Message)")
    }
    finally {
        if ($ds)   { try { $ds.Dispose() } catch { Write-Verbose "Ignoring error while closing SK LDAP search: $($_.Exception.Message)" } }
        if ($ldap) { try { $ldap.Dispose() } catch { Write-Verbose "Ignoring error while closing SK LDAP connection: $($_.Exception.Message)" } }
    }

    # 2. Search Thales / Zetes LDAP (ldap.eidpki.ee) - ESTEID2025
    $thalesUrl  = $script:ThalesLdapURL
    $thalesPort = $script:ThalesLdapPort
    $thalesDN   = $script:ThalesLdapDN

    $thalesLdap = $null
    $thalesDs   = $null
    try {
        $thalesLdapDn = "LDAP://$thalesUrl`:$thalesPort/$thalesDN"
        # FastBind required to avoid 0x80005000 schema discovery errors on Zetes
        $thalesAuth = [System.DirectoryServices.AuthenticationTypes]::FastBind
        $thalesLdap = New-Object System.DirectoryServices.DirectoryEntry($thalesLdapDn, $null, $null, $thalesAuth)

        $thalesDs = New-Object System.DirectoryServices.DirectorySearcher($thalesLdap)
        $thalesDs.Filter = $IDCodeFilter
        [void]$thalesDs.PropertiesToLoad.Add("usercertificate;binary")

        $thalesResults = $thalesDs.FindAll()
        foreach ($result in $thalesResults) {
            if ($result.Path -like "*ou=Authentication*") {
                if ($result.Properties['usercertificate;binary'].Count -gt 0) {
                    $rawVal = $result.Properties['usercertificate;binary'][0]
                    $byteCert = if ($rawVal -is [byte[]]) {
                        $rawVal
                    } else {
                        [Convert]::FromBase64String($rawVal.ToString())
                    }
                    if ($byteCert -and $byteCert.Length -gt 0) {
                        $discoveredCerts.Add($byteCert)
                    }
                }
            }
        }
    }
    catch {
        Write-Verbose "Could not query Thales/Zetes LDAP ($thalesUrl): $($_.Exception.Message)"
        $errors.Add("${thalesUrl}: $($_.Exception.Message)")
    }
    finally {
        if ($thalesDs)   { try { $thalesDs.Dispose() } catch { Write-Verbose "Ignoring error while closing Zetes LDAP search: $($_.Exception.Message)" } }
        if ($thalesLdap) { try { $thalesLdap.Dispose() } catch { Write-Verbose "Ignoring error while closing Zetes LDAP connection: $($_.Exception.Message)" } }
    }

    if ($errors.Count -gt 0) {
        $errSummary = $errors -join "; "
        throw "LDAP lookup for ID '$ID' is incomplete: $errSummary"
    }

    $validCerts = [System.Collections.Generic.List[byte[]]]::new()
    foreach ($bytes in $discoveredCerts) {
        $problem = _getCertificateProblem -CertBytes $bytes -ID $ID
        if ($problem) {
            Write-Verbose "Skipping LDAP certificate for ID '$ID': $problem"
        }
        else {
            $validCerts.Add($bytes)
        }
    }

    $certArray = $validCerts.ToArray()
    if ($UseCache -and $certArray.Count -gt 0) {
        _setCachedCertificates -ID $ID -CertBytesList $certArray
    }

    return , $certArray
}
