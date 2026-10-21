#
# NPU-EstonianID - Common LDAP & Cache Engine
#

$script:EstIDLdapURL = "esteid.ldap.sk.ee"
$script:EstIDLdapPort = 636
$script:EstIDLdapDN = "dc=ESTEID,c=EE"

$script:ThalesLdapURL = "ldap.eidpki.ee"
$script:ThalesLdapPort = 636
$script:ThalesLdapDN = "dc=ldap,dc=eidpki,dc=ee"

# Caching Configuration (Protects against Zetes 60 req/hr rate limits)
$script:CacheFolder = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath 'NPU_EstID_Cache_v2'
$script:CacheTTLHours = 24
$script:MemoryCache = @{}

function Get-CachedCertificates {
    param([string]$ID)

    # 1. Check in-memory cache
    if ($script:MemoryCache.ContainsKey($ID)) {
        $entry = $script:MemoryCache[$ID]
        if ((([DateTime]::UtcNow) - $entry.Timestamp).TotalHours -lt $script:CacheTTLHours) {
            return , $entry.CertBytesList
        }
    }

    # 2. Check disk cache
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
        } catch { }
    }
    return $null
}

function Set-CachedCertificates {
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
    } catch { }
}

function Get-LdapCertificatesInternal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ID,

        [Parameter()]
        [switch]$UseCache
    )

    if ($UseCache) {
        $cached = Get-CachedCertificates -ID $ID
        if ($cached -and $cached.Count -gt 0) {
            Write-Verbose "Retrieved certificate(s) for ID '$ID' from cache."
            return $cached
        }
    }

    $discoveredCerts = [System.Collections.Generic.List[byte[]]]::new()
    $IDCodeFilter = "(serialNumber=PNOEE-$ID)"
    $errors = [System.Collections.Generic.List[string]]::new()

    # 1. Search SK ID Solutions LDAP (esteid.ldap.sk.ee) - ESTEID2018
    $skUrl  = if ($global:EstIDLdapURL)  { $global:EstIDLdapURL }  else { $script:EstIDLdapURL }
    $skPort = if ($global:EstIDLdapPort) { $global:EstIDLdapPort } else { $script:EstIDLdapPort }
    $skDN   = if ($global:EstIDLdapDN)   { $global:EstIDLdapDN }   else { $script:EstIDLdapDN }

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
        if ($ds)   { try { $ds.Dispose() } catch { } }
        if ($ldap) { try { $ldap.Dispose() } catch { } }
    }

    # 2. Search Thales / Zetes LDAP (ldap.eidpki.ee) - ESTEID2025
    $thalesUrl  = if ($global:ThalesLdapURL)  { $global:ThalesLdapURL }  else { $script:ThalesLdapURL }
    $thalesPort = if ($global:ThalesLdapPort) { $global:ThalesLdapPort } else { $script:ThalesLdapPort }
    $thalesDN   = if ($global:ThalesLdapDN)   { $global:ThalesLdapDN }   else { $script:ThalesLdapDN }

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
        if ($thalesDs)   { try { $thalesDs.Dispose() } catch { } }
        if ($thalesLdap) { try { $thalesLdap.Dispose() } catch { } }
    }

    if ($errors.Count -gt 0) {
        $errSummary = $errors -join "; "
        throw "LDAP lookup for ID '$ID' is incomplete: $errSummary"
    }

    $certArray = $discoveredCerts.ToArray()
    if ($UseCache -and $certArray.Count -gt 0) {
        Set-CachedCertificates -ID $ID -CertBytesList $certArray
    }

    return , $certArray
}
