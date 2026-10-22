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

# Longest wait for one directory's search results
$script:LdapTimeoutSeconds = 15

# Caching Configuration (Protects against Zetes 60 req/hr rate limits)
# Kept in the user profile, not %TEMP%: whoever can write the cache decides who Protect-Cdoc encrypts to,
# and for SYSTEM %TEMP% is C:\Windows\Temp, which every local user can write to.
$localAppData = [Environment]::GetFolderPath('LocalApplicationData')
$script:CacheFolder = if ($localAppData) { Join-Path -Path $localAppData -ChildPath 'NPU-EstonianID\CertCache' } else { $null }
$script:CacheTTLHours = 24
$script:MemoryCache = @{}

# Card types the module uses. 'IdCard' is the person's ID card (SK or Zetes); 'DigiId' is the SK Digi-ID (blue card).
$script:CardTypes = @('IdCard', 'DigiId')

# The directories in search order. CardTypes maps an entry's o= branch (under ou=Authentication) to a card type;
# other branches (Mobile-ID, e-resident and residence permit cards) are skipped.
function _getLdapDirectories {
    @(
        [pscustomobject]@{
            Name               = 'SK ID Solutions'
            Server             = $script:EstIDLdapURL
            Port               = $script:EstIDLdapPort
            BaseDN             = $script:EstIDLdapDN
            AuthenticationType = 'Anonymous'
            CardTypes          = @{ 'Identity card of Estonian citizen' = 'IdCard'; 'Digital identity card' = 'DigiId' }
        }
        [pscustomobject]@{
            Name               = 'Zetes'
            Server             = $script:ThalesLdapURL
            Port               = $script:ThalesLdapPort
            BaseDN             = $script:ThalesLdapDN
            # FastBind required to avoid 0x80005000 schema discovery errors on Zetes
            AuthenticationType = 'FastBind'
            CardTypes          = @{ 'IdentityCardEstonianCitizen' = 'IdCard' }
        }
    )
}

# Queries one LDAP directory and returns its raw entries: Path (the entry's LDAP path) and Value (the first
# userCertificate;binary value, as returned by the directory). The only function that talks to the network;
# the tests replace it with fake directory answers.
function _searchLdapDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server,

        [Parameter(Mandatory = $true)]
        [int]$Port,

        [Parameter(Mandatory = $true)]
        [string]$BaseDN,

        [Parameter(Mandatory = $true)]
        [string]$AuthenticationType,

        [Parameter(Mandatory = $true)]
        [string]$Filter
    )

    $entry = $null
    $searcher = $null
    $results = $null
    try {
        $auth = [System.DirectoryServices.AuthenticationTypes]$AuthenticationType
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server`:$Port/$BaseDN", $null, $null, $auth)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
        $searcher.Filter = $Filter
        $searcher.ClientTimeout = [TimeSpan]::FromSeconds($script:LdapTimeoutSeconds)
        $searcher.ServerTimeLimit = [TimeSpan]::FromSeconds($script:LdapTimeoutSeconds)
        [void]$searcher.PropertiesToLoad.Add('usercertificate;binary')

        $results = $searcher.FindAll()
        foreach ($result in $results) {
            $values = $result.Properties['usercertificate;binary']
            if ($values.Count -gt 0) {
                [pscustomobject]@{ Path = $result.Path; Value = $values[0] }
            }
        }
    }
    finally {
        if ($results)  { try { $results.Dispose() } catch { Write-Verbose "Ignoring error while closing $Server search results: $($_.Exception.Message)" } }
        if ($searcher) { try { $searcher.Dispose() } catch { Write-Verbose "Ignoring error while closing $Server LDAP search: $($_.Exception.Message)" } }
        if ($entry)    { try { $entry.Dispose() } catch { Write-Verbose "Ignoring error while closing $Server LDAP connection: $($_.Exception.Message)" } }
    }
}

# Card type of an LDAP entry, from the o= branch under ou=Authentication in its path; $null if the
# directory's CardTypes does not list it
function _getCardType {
    param(
        [string]$Path,
        [hashtable]$CardTypes
    )

    $dn = $Path -replace '^LDAP://[^/]*/', ''
    # Split on commas that are not escaped (the CN contains "SURNAME\,GIVENNAME\,CODE")
    $parts = @([regex]::Split($dn, '(?<!\\),') | ForEach-Object { $_.Trim() })
    if ($parts -notcontains 'ou=Authentication') {
        return $null
    }
    foreach ($part in $parts) {
        if ($part -match '^o=(.+)$' -and $CardTypes.ContainsKey($Matches[1])) {
            return $CardTypes[$Matches[1]]
        }
    }
    return $null
}

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

# Cached lookup result for a personal code: CardType + CertBytes entries, or nothing (so @() stays empty)
function _getCachedCertificates {
    param([string]$ID)

    # 1. Check in-memory cache
    if ($script:MemoryCache.ContainsKey($ID)) {
        $memoryEntry = $script:MemoryCache[$ID]
        if ((([DateTime]::UtcNow) - $memoryEntry.Timestamp).TotalHours -lt $script:CacheTTLHours) {
            return $memoryEntry.Entries
        }
    }

    # 2. Check disk cache
    if (-not $script:CacheFolder) {
        return
    }
    $cacheFile = Join-Path -Path $script:CacheFolder -ChildPath "$ID.json"
    if (Test-Path -LiteralPath $cacheFile) {
        try {
            $data = Get-Content -LiteralPath $cacheFile -Raw | ConvertFrom-Json
            if (-not $data.Certificates) {
                # Written by an older version without card types: look the person up again
                Write-Verbose "Ignoring cache file '$cacheFile' without card types."
                return
            }
            $timestamp = [DateTime]::Parse($data.Timestamp, [System.Globalization.CultureInfo]::InvariantCulture)
            if ((([DateTime]::UtcNow) - $timestamp).TotalHours -lt $script:CacheTTLHours) {
                $entries = @(foreach ($item in $data.Certificates) {
                    [pscustomobject]@{ CardType = [string]$item.CardType; CertBytes = [Convert]::FromBase64String($item.Base64) }
                })
                $script:MemoryCache[$ID] = @{
                    Timestamp = $timestamp
                    Entries   = $entries
                }
                return $entries
            }
        } catch {
            Write-Verbose "Ignoring unreadable cache file '$cacheFile': $($_.Exception.Message)"
        }
    }
    return
}

function _setCachedCertificates {
    param(
        [string]$ID,
        [object[]]$Entries
    )
    $now = [DateTime]::UtcNow
    # 1. Store in memory
    $script:MemoryCache[$ID] = @{
        Timestamp = $now
        Entries   = $Entries
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
        $obj = @{
            Timestamp    = $now.ToString("o")
            Certificates = @(foreach ($entry in $Entries) { @{ CardType = $entry.CardType; Base64 = [Convert]::ToBase64String($entry.CertBytes) } })
        }
        $json = ConvertTo-Json -InputObject $obj -Depth 3
        Set-Content -LiteralPath $cacheFile -Value $json -Encoding utf8
    } catch {
        Write-Verbose "Could not write the certificate cache for ID '$ID': $($_.Exception.Message)"
    }
}

# Looks up a person's ID card and Digi-ID authentication certificates. Returns CardType + CertBytes entries.
#
# A person has at most one ID card, from SK or from Zetes, and possibly an SK Digi-ID. SK is searched first;
# once an ID card has been found, Zetes is not searched. A Digi-ID alone does not stop the search, because its
# owner may have a Zetes ID card. If a directory that has to be searched cannot be reached, the lookup fails
# as a whole and nothing is cached, so callers never act on a partial answer.
function _getLdapCertificates {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ID,

        [Parameter()]
        [switch]$UseCache
    )

    if ($UseCache) {
        $cached = @(_getCachedCertificates -ID $ID)
        if ($cached.Count -gt 0) {
            $problems = @(foreach ($entry in $cached) {
                if ($script:CardTypes -notcontains $entry.CardType) { "unknown card type '$($entry.CardType)'" }
                _getCertificateProblem -CertBytes $entry.CertBytes -ID $ID
            }) | Where-Object { $_ }
            if (@($problems).Count -eq 0) {
                Write-Verbose "Retrieved certificate(s) for ID '$ID' from cache."
                foreach ($entry in $cached) {
                    $entry
                }
                return
            }
            Write-Warning "Ignoring cached certificate(s) for ID '$ID' and querying LDAP instead: $($problems -join '; ')"
            $script:MemoryCache.Remove($ID)
        }
    }

    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($directory in _getLdapDirectories) {
        try {
            $entries = @(_searchLdapDirectory -Server $directory.Server -Port $directory.Port -BaseDN $directory.BaseDN `
                -AuthenticationType $directory.AuthenticationType -Filter "(serialNumber=PNOEE-$ID)")
        }
        catch {
            Write-Verbose "Could not query $($directory.Name) LDAP ($($directory.Server)): $($_.Exception.Message)"
            throw "LDAP lookup for ID '$ID' is incomplete: $($directory.Server): $($_.Exception.Message)"
        }

        foreach ($entry in $entries) {
            $cardType = _getCardType -Path $entry.Path -CardTypes $directory.CardTypes
            if (-not $cardType) {
                Write-Verbose "Skipping $($directory.Name) entry '$($entry.Path)': not an ID card or Digi-ID authentication certificate."
                continue
            }
            try {
                [byte[]]$bytes = if ($entry.Value -is [byte[]]) { $entry.Value } else { [Convert]::FromBase64String($entry.Value.ToString()) }
            }
            catch {
                Write-Verbose "Skipping $($directory.Name) entry '$($entry.Path)': unreadable certificate value."
                continue
            }
            $problem = _getCertificateProblem -CertBytes $bytes -ID $ID
            if ($problem) {
                Write-Verbose "Skipping $($directory.Name) certificate for ID '$ID': $problem"
                continue
            }
            $found.Add([pscustomobject]@{ CardType = $cardType; CertBytes = $bytes })
        }

        if (@($found | Where-Object { $_.CardType -eq 'IdCard' }).Count -gt 0) {
            Write-Verbose "ID card found in $($directory.Name) LDAP; no further directories searched."
            break
        }
    }

    if ($UseCache -and $found.Count -gt 0) {
        _setCachedCertificates -ID $ID -Entries $found.ToArray()
    }
    foreach ($item in $found) {
        $item
    }
}
