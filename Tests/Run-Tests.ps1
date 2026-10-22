#
# NPU-EstonianID - Automated Test Suite
#

$ErrorActionPreference = 'Stop'
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Running NPU-EstonianID Test Suite on PS Version $($PSVersionTable.PSVersion)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$modulePath = Resolve-Path (Join-Path -Path $PSScriptRoot -ChildPath '..\NPU-EstonianID\NPU-EstonianID.psd1')
Write-Host "[1/13] Importing Module from: $modulePath"
Import-Module $modulePath -Force

# Points the module's LDAP directories at other servers; without arguments restores the real ones.
# Tests use a closed local port so that lookups fail fast or come from the cache, without network access.
$realLdap = & (Get-Module NPU-EstonianID) { @{ SK = $script:EstIDLdapURL; SKPort = $script:EstIDLdapPort; Zetes = $script:ThalesLdapURL; ZetesPort = $script:ThalesLdapPort } }
function Set-TestLdapServer {
    param(
        [string]$SK = $realLdap.SK, [int]$SKPort = $realLdap.SKPort,
        [string]$Zetes = $realLdap.Zetes, [int]$ZetesPort = $realLdap.ZetesPort
    )
    & (Get-Module NPU-EstonianID) {
        param($skUrl, $skPort, $zetesUrl, $zetesPort)
        $script:EstIDLdapURL = $skUrl; $script:EstIDLdapPort = $skPort
        $script:ThalesLdapURL = $zetesUrl; $script:ThalesLdapPort = $zetesPort
    } $SK $SKPort $Zetes $ZetesPort
}

# Verify exported commands
$exported = Get-Command -Module NPU-EstonianID
Write-Host "Exported commands: $($exported.Name -join ', ')"
if (-not ($exported.Name -contains 'Protect-Cdoc')) {
    throw "Protect-Cdoc is not exported!"
}
if (-not ($exported.Name -contains 'Get-EstEIDCertificate')) {
    throw "Get-EstEIDCertificate is not exported!"
}

# 2. Test Soft ActiveDirectory check
Write-Host "`n[2/13] Testing Soft Active Directory dependency check..."
try {
    Get-ADUserEstonianIDMapping -Identity "testuser" -ErrorAction Stop
    Write-Warning "ActiveDirectory module is present on this system."
}
catch {
    if ($_.Exception.Message -match "ActiveDirectory.*is required") {
        Write-Host " PASS: Soft check cleanly detected missing RSAT/AD module without breaking module load." -ForegroundColor Green
    }
    else {
        Write-Host " Caught error: $($_.Exception.Message)"
    }
}

# 3. Load Test Certificates
Write-Host "`n[3/13] Loading Test Certificates (2018 SK and 2025 Zetes)..."
$cert2018Path = Join-Path -Path $PSScriptRoot -ChildPath 'cert_esteid2018_test.cer'
$cert2025Path = Join-Path -Path $PSScriptRoot -ChildPath 'cert_esteid2025_test.cer'

$cert2018 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Get-Item $cert2018Path).FullName)
$cert2025 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Get-Item $cert2025Path).FullName)

$name2018 = $cert2018.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
$name2025 = $cert2025.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)

Write-Host " Cert 2018 Subject SimpleName: $name2018"
Write-Host " Cert 2025 Subject SimpleName: $name2025"

if ([string]::IsNullOrWhiteSpace($name2025)) {
    throw "Failed to extract SimpleName from 2025 Zetes cert!"
}
Write-Host " PASS: SimpleName correctly extracted for both card generations." -ForegroundColor Green

# 4. Test Strong Name Mapping string generation
Write-Host "`n[4/13] Testing Strong Name Mapping Generation (Get-IDUserMapping)..."
$mapping2018 = Get-IDUserMapping -Certificate $cert2018
$mapping2025 = Get-IDUserMapping -Certificate $cert2025
Write-Host " 2018 Mapping: $mapping2018"
Write-Host " 2025 Mapping: $mapping2025"

if (-not $mapping2018.StartsWith("X509:<I>") -or -not $mapping2018.Contains("<SR>")) {
    throw "Invalid mapping format for 2018 cert!"
}
if (-not $mapping2025.StartsWith("X509:<I>") -or -not $mapping2025.Contains("<SR>")) {
    throw "Invalid mapping format for 2025 cert!"
}
Write-Host " PASS: Strong name mapping strings generated successfully." -ForegroundColor Green

# 5. Test CDOC 1.0 Encryption for 2025 Zetes Card
Write-Host "`n[5/13] Testing CDOC Encryption with 2025 Zetes Card (Native PS & bcrypt.dll)..."
$testPlaintext = "Hello Estonian ID! This is a confidential test encrypted with pure native PowerShell."
$testFile = Join-Path -Path $env:TEMP -ChildPath "npu_test_doc.txt"
[System.IO.File]::WriteAllText($testFile, $testPlaintext)
$testCdoc2025 = Join-Path -Path $env:TEMP -ChildPath "npu_test_2025.cdoc"
if (Test-Path $testCdoc2025) { Remove-Item $testCdoc2025 -Force }

Protect-Cdoc -InputFile $testFile -Out $testCdoc2025 -Certificate $cert2025 -Verbose
if (-not (Test-Path $testCdoc2025)) {
    throw "Output CDOC file was not created!"
}

# Verify XML structure and Recipient attribute
$cdocXml = [xml](Get-Content -Raw -Encoding UTF8 -LiteralPath $testCdoc2025)
$encKey = $cdocXml.EncryptedData.KeyInfo.EncryptedKey
Write-Host " Generated CDOC Recipient attribute: '$($encKey.Recipient)'"
if ($encKey.Recipient -ne $name2025) {
    throw "Recipient attribute does NOT match expected SimpleName! Expected '$name2025', got '$($encKey.Recipient)'"
}
Write-Host " PASS: Recipient attribute is non-empty and matches '$name2025' perfectly!" -ForegroundColor Green

# 6. Test Multi-Recipient Encryption (2018 + 2025 cards)
Write-Host "`n[6/13] Testing Multi-Recipient Encryption (2018 + 2025 simultaneously)..."
$testCdocMulti = Join-Path -Path $env:TEMP -ChildPath "npu_test_multi.cdoc"
if (Test-Path $testCdocMulti) { Remove-Item $testCdocMulti -Force }

Protect-Cdoc -InputFile $testFile -Out $testCdocMulti -Certificate $cert2018, $cert2025
$multiXml = [xml](Get-Content -Raw -Encoding UTF8 -LiteralPath $testCdocMulti)
$encKeys = @($multiXml.EncryptedData.KeyInfo.EncryptedKey)
Write-Host " Number of EncryptedKey elements: $($encKeys.Count)"
if ($encKeys.Count -ne 2) {
    throw "Expected 2 EncryptedKey elements, got $($encKeys.Count)"
}
Write-Host " Recipient 1: $($encKeys[0].Recipient)"
Write-Host " Recipient 2: $($encKeys[1].Recipient)"
Write-Host " PASS: Multi-recipient CDOC container generated with 2 keys." -ForegroundColor Green

# 7. Test In-Memory String Encryption
Write-Host "`n[7/13] Testing In-Memory String Encryption (-InputString)..."
$testCdocString = Join-Path -Path $env:TEMP -ChildPath "npu_test_string.cdoc"
if (Test-Path $testCdocString) { Remove-Item $testCdocString -Force }

"Top secret in-memory string" | Protect-Cdoc -FileName "secret.txt" -Out $testCdocString -Certificate $cert2025
$stringXml = [xml](Get-Content -Raw -Encoding UTF8 -LiteralPath $testCdocString)
$origFileProp = ($stringXml.EncryptedData.EncryptionProperties.EncryptionProperty | Where-Object { $_.Name -eq 'orig_file' }).'#text'
Write-Host " orig_file property: $origFileProp"
if ($origFileProp -ne "secret.txt|27|application/octet-stream|D0") {
    throw "Unexpected orig_file property: '$origFileProp'"
}
Write-Host " PASS: In-memory string encrypted with exact filename and size metadata." -ForegroundColor Green

# Several piped lines (including a blank one) become ONE document with default names pipe.txt / pipe.cdoc
$pipeDir = Join-Path -Path $env:TEMP -ChildPath "npu_test_pipe"
if (Test-Path -LiteralPath $pipeDir) { Remove-Item -LiteralPath $pipeDir -Recurse -Force }
$null = New-Item -ItemType Directory -Path $pipeDir
Push-Location $pipeDir
try {
    'line one', '', 'line three' | Protect-Cdoc -Certificate $cert2025
    $pipeFiles = @(Get-ChildItem -LiteralPath $pipeDir)
    if ($pipeFiles.Count -ne 1 -or $pipeFiles[0].Name -ne 'pipe.cdoc') {
        throw "Expected exactly one 'pipe.cdoc', got: $($pipeFiles.Name -join ', ')"
    }
    $pipeXml = [xml](Get-Content -Raw -Encoding UTF8 -LiteralPath $pipeFiles[0].FullName)
    $pipeProp = ($pipeXml.EncryptedData.EncryptionProperties.EncryptionProperty | Where-Object { $_.Name -eq 'orig_file' }).'#text'
    $expectedSize = [System.Text.Encoding]::UTF8.GetByteCount(('line one', '', 'line three') -join [System.Environment]::NewLine)
    if ($pipeProp -ne "pipe.txt|$expectedSize|application/octet-stream|D0") {
        throw "Unexpected orig_file property for piped lines: '$pipeProp'"
    }

    # File objects from Get-ChildItem still bind to -InputFile
    Remove-Item -LiteralPath $pipeFiles[0].FullName
    [System.IO.File]::WriteAllText((Join-Path $pipeDir 'report.pdf'), 'pdf bytes')
    Get-ChildItem -LiteralPath $pipeDir -Filter '*.pdf' | Protect-Cdoc -Certificate $cert2025
    if (-not (Test-Path -LiteralPath (Join-Path $pipeDir 'report.pdf.cdoc'))) {
        throw "Piped FileInfo did not produce 'report.pdf.cdoc'"
    }
}
finally {
    Pop-Location
    Remove-Item -LiteralPath $pipeDir -Recurse -Force
}
Write-Host " PASS: Piped lines encrypted as a single 'pipe.txt' inside 'pipe.cdoc'." -ForegroundColor Green

# 8. Test Incomplete LDAP Directory Outage Handling
Write-Host "`n[8/13] Testing Incomplete LDAP Outage Handling (Failure Isolation & Zero Caching)..."
$v2CacheDir = & (Get-Module NPU-EstonianID) { $script:CacheFolder }
$fakeID = '00000000000'
$fakeCacheFile = Join-Path -Path $v2CacheDir -ChildPath "$fakeID.json"
if (Test-Path -LiteralPath $fakeCacheFile) {
    Remove-Item -LiteralPath $fakeCacheFile -Force
}

$tempCdocFail = Join-Path -Path $env:TEMP -ChildPath "npu_test_fail.cdoc"
if (Test-Path -LiteralPath $tempCdocFail) {
    Remove-Item -LiteralPath $tempCdocFail -Force
}

try {
    Set-TestLdapServer -Zetes '127.0.0.1' -ZetesPort 1

    # 1. Assert Get-EstEIDCertificate throws with 'incomplete' and '127.0.0.1'
    $threwCert = $false
    try {
        Get-EstEIDCertificate -ID $fakeID -UseCache -ErrorAction Stop
    }
    catch {
        $threwCert = $true
        $msg = $_.Exception.Message
        if ($msg -notmatch 'incomplete' -or $msg -notmatch '127\.0\.0\.1') {
            throw "Expected error message containing 'incomplete' and '127.0.0.1', got: '$msg'"
        }
        Write-Host " Caught expected error from Get-EstEIDCertificate: $msg"
    }
    if (-not $threwCert) {
        throw "Get-EstEIDCertificate did not throw on LDAP failure!"
    }

    # 2. Assert no cache file exists in v2 cache folder
    if (Test-Path -LiteralPath $fakeCacheFile) {
        throw "Cache file '$fakeCacheFile' should not exist after failed lookup!"
    }
    Write-Host " PASS: Verified no cache file written for incomplete lookup." -ForegroundColor Green

    # 3. Assert Protect-Cdoc throws and creates no file
    $threwProtect = $false
    try {
        Protect-Cdoc -InputString 'x' -ID $fakeID -Out $tempCdocFail -ErrorAction Stop
    }
    catch {
        $threwProtect = $true
        Write-Host " Caught expected error from Protect-Cdoc: $($_.Exception.Message)"
    }
    if (-not $threwProtect) {
        throw "Protect-Cdoc did not throw on LDAP failure!"
    }
    if (Test-Path -LiteralPath $tempCdocFail) {
        throw "Output file '$tempCdocFail' was created despite failed lookup!"
    }
    Write-Host " PASS: Protect-Cdoc aborted cleanly and created no output file." -ForegroundColor Green

    # 4. Assert directory is not created on failure
    $noDir = Join-Path $env:TEMP ("npu_nodir_" + [guid]::NewGuid().ToString('N'))
    $threwNoDir = $false
    try {
        Protect-Cdoc -InputString 'x' -ID '00000000000' -Out (Join-Path $noDir 'out.cdoc') -ErrorAction Stop
    }
    catch {
        $threwNoDir = $true
    }
    if (-not $threwNoDir) {
        throw "Protect-Cdoc did not throw on LDAP failure with non-existent destination directory!"
    }
    if (Test-Path -LiteralPath $noDir) {
        throw "Directory '$noDir' should not exist after failed Protect-Cdoc!"
    }
    Write-Host " PASS: Destination directory was not created on lookup failure." -ForegroundColor Green

    # 5. Assert pipeline continues past failures
    $ev = $null
    $null = '00000000000','00000000001' | Get-IDUserMapping -ErrorAction SilentlyContinue -ErrorVariable ev
    # -ErrorVariable on an advanced function also captures errors from nested calls,
    # so only count the records Get-IDUserMapping itself emitted.
    $own = @($ev | Where-Object { $_.FullyQualifiedErrorId -eq 'EstEIDLookupIncomplete,Get-IDUserMapping' })
    if ($own.Count -ne 2) {
        throw "Expected 2 EstEIDLookupIncomplete errors from Get-IDUserMapping, got $($own.Count)"
    }
    $targets = @($own | ForEach-Object { $_.TargetObject }) -join ','
    if ($targets -ne '00000000000,00000000001') {
        throw "Expected errors for both IDs in order, got targets '$targets'"
    }
    Write-Host " PASS: Pipeline continues past failures and preserves error ID." -ForegroundColor Green

    # 6. Assert Stop still stops Get-IDUserMapping
    $threwStop = $false
    try {
        Get-IDUserMapping -EstonianID '00000000000' -ErrorAction Stop
    }
    catch {
        $threwStop = $true
    }
    if (-not $threwStop) {
        throw "Get-IDUserMapping with -ErrorAction Stop did not throw on failed lookup!"
    }
    Write-Host " PASS: Get-IDUserMapping -ErrorAction Stop throws terminating error as expected." -ForegroundColor Green

    Write-Host " PASS: Incomplete LDAP outage handling verified." -ForegroundColor Green
}
finally {
    Set-TestLdapServer
    if (Test-Path -LiteralPath $tempCdocFail) {
        Remove-Item -LiteralPath $tempCdocFail -Force -ErrorAction SilentlyContinue
    }
    if ($noDir -and (Test-Path -LiteralPath $noDir)) {
        Remove-Item -LiteralPath $noDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# 9. Decryption Round-Trip Test (End-to-End Key Unwrap + AES-GCM Decrypt)
Write-Host "`n[9/13] Testing Full Decryption Round-Trip (ECDH + Key Unwrap + AES-GCM Decrypt)..."
if ($PSVersionTable.PSVersion.Major -ge 7) {
    if (-not ([System.Management.Automation.PSTypeName]'KwUnwrap').Type) {
        Add-Type -TypeDefinition @"
        using System; using System.Security.Cryptography;
        public static class KwUnwrap {
          public static byte[] Unwrap(byte[] kek, byte[] c) {
            int n = c.Length/8 - 1; byte[] a = new byte[8]; Buffer.BlockCopy(c,0,a,0,8);
            byte[][] r = new byte[n+1][]; for (int i=1;i<=n;i++){ r[i]=new byte[8]; Buffer.BlockCopy(c,i*8,r[i],0,8);}
            using (Aes aes = Aes.Create()) { aes.Key=kek; aes.Mode=CipherMode.ECB; aes.Padding=PaddingMode.None;
              var d = aes.CreateDecryptor(); byte[] b=new byte[16], o=new byte[16];
              for (int j=5;j>=0;j--) for (int i=n;i>=1;i--) { ulong t=(ulong)(n*j+i);
                for(int k=0;k<8;k++) b[k]=(byte)(a[k]^(byte)(t>>((7-k)*8)));
                Buffer.BlockCopy(r[i],0,b,8,8); d.TransformBlock(b,0,16,o,0);
                Buffer.BlockCopy(o,0,a,0,8); Buffer.BlockCopy(o,8,r[i],0,8);} }
            for(int k=0;k<8;k++) if (a[k]!=0xA6) throw new CryptographicException("KW integrity check failed");
            byte[] p=new byte[n*8]; for(int i=1;i<=n;i++) Buffer.BlockCopy(r[i],0,p,(i-1)*8,8); return p; }
        }
"@
    }

    $curve = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP384')
    $b = [System.Security.Cryptography.ECDiffieHellman]::Create($curve)
    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Recipient', [System.Security.Cryptography.ECDsa]::Create($b.ExportParameters($true)), [System.Security.Cryptography.HashAlgorithmName]::SHA384)
    $selfCert = $req.CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1), [DateTimeOffset]::Now.AddDays(1))

    $rtOut = Join-Path $env:TEMP 'rt_test.cdoc'
    $expectedLines = 'Hello round trip', '', 'decryption test!'
    $expectedMessage = $expectedLines -join [System.Environment]::NewLine
    $expectedLines | Protect-Cdoc -FileName 'test.txt' -Out $rtOut -Certificate $selfCert
    
    $xmlDoc = [xml](Get-Content -Raw -Encoding UTF8 $rtOut)
    Remove-Item $rtOut -Force

    $ns = @{d='http://www.w3.org/2001/04/xmlenc#'; ds='http://www.w3.org/2000/09/xmldsig#'; x11='http://www.w3.org/2009/xmlenc11#'; s11='http://www.w3.org/2009/xmldsig11#'}
    $ekNode = (Select-Xml -Xml $xmlDoc -XPath '//d:EncryptedKey' -Namespace $ns).Node
    $ephBytes = [Convert]::FromBase64String((Select-Xml -Xml $ekNode -XPath './/s11:PublicKey' -Namespace $ns).Node.InnerText)
    $wrappedBytes = [Convert]::FromBase64String((Select-Xml -Xml $ekNode -XPath './d:CipherData/d:CipherValue' -Namespace $ns).Node.InnerText)
    $payloadBytes = [Convert]::FromBase64String((Select-Xml -Xml $xmlDoc -XPath '/d:EncryptedData/d:CipherData/d:CipherValue' -Namespace $ns).Node.InnerText)

    $ecParams = [System.Security.Cryptography.ECParameters]::new()
    $ecParams.Curve = $curve
    $ecPoint = [System.Security.Cryptography.ECPoint]::new()
    $ecPoint.X = $ephBytes[1..48]
    $ecPoint.Y = $ephBytes[49..96]
    $ecParams.Q = $ecPoint
    
    $peerPub = [System.Security.Cryptography.ECDiffieHellman]::Create($ecParams).PublicKey
    $sharedSecret = $b.DeriveRawSecretAgreement($peerPub)
    $kek = [CdocCryptoEngine]::ConcatKdfSha384($sharedSecret, [System.Text.Encoding]::ASCII.GetBytes('ENCDOC-XML|1.1'), $ephBytes, $selfCert.RawData, 32)

    $transportKey = [KwUnwrap]::Unwrap($kek, $wrappedBytes)
    $aesGcm = [System.Security.Cryptography.AesGcm]::new($transportKey, 16)
    $ciphertext = $payloadBytes[12..($payloadBytes.Length - 17)]
    $decrypted = [byte[]]::new($ciphertext.Length)
    $iv = $payloadBytes[0..11]
    $tag = $payloadBytes[($payloadBytes.Length - 16)..($payloadBytes.Length - 1)]
    $aesGcm.Decrypt($iv, [byte[]]$ciphertext, $tag, $decrypted)

    $recoveredString = [System.Text.Encoding]::UTF8.GetString($decrypted)
    Write-Host " Recovered plaintext: '$recoveredString'"
    if ($recoveredString -ne $expectedMessage) {
        throw "Decrypted text mismatch! Expected '$expectedMessage', got '$recoveredString'"
    }
    Write-Host " PASS: Decryption round-trip verified end-to-end!" -ForegroundColor Green
}
else {
    Write-Host " SKIP: requires PowerShell 7" -ForegroundColor Yellow
}

# 10. OU batch reports Set-ADUser failures (fake ActiveDirectory module, cached certificate, no network)
Write-Host "`n[10/13] Testing Set-ADOUEstonianIDMapping failure reporting (mock Active Directory)..."
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Write-Host " SKIP: real ActiveDirectory module is installed; not shadowing it with a mock" -ForegroundColor Yellow
}
else {
    # Cached certificates must belong to the personal code, so use the one in the 2025 test certificate
    $adTestId = '60001019906'
    $adCacheDir = & (Get-Module NPU-EstonianID) { $script:CacheFolder }
    $adCacheFile = Join-Path -Path $adCacheDir -ChildPath "$adTestId.json"
    $adCacheBackup = if (Test-Path -LiteralPath $adCacheFile) { Get-Content -LiteralPath $adCacheFile -Raw }
    try {
        # Seed the disk cache so the lookup never touches LDAP; point LDAP at a closed port so any hit fails loudly
        $null = New-Item -ItemType Directory -Path $adCacheDir -Force
        @{
            Timestamp   = [DateTime]::UtcNow.ToString('o')
            Base64Certs = @([Convert]::ToBase64String([System.IO.File]::ReadAllBytes($cert2025Path)))
        } | ConvertTo-Json | Set-Content -LiteralPath $adCacheFile -Encoding utf8
        Set-TestLdapServer -SK '127.0.0.1' -SKPort 1 -Zetes '127.0.0.1' -ZetesPort 1

        New-Module -Name ActiveDirectory -ScriptBlock {
            function Get-ADUser {
                param($Filter, $SearchBase, $Properties, $Identity)
                $all = @(
                    [PSCustomObject]@{ SamAccountName = 'ok.user';   isikukood = '60001019906'; altSecurityIdentities = @() }
                    [PSCustomObject]@{ SamAccountName = 'fail.user'; isikukood = '60001019906'; altSecurityIdentities = @() }
                )
                if ($Identity) { $all | Where-Object { $_.SamAccountName -eq $Identity } } else { $all }
            }
            function Set-ADUser {
                [CmdletBinding()]
                param($Identity, $Replace, $Add)
                # Real Set-ADUser failures are non-terminating by default
                if ($Identity.SamAccountName -eq 'fail.user') { Write-Error 'Insufficient access rights to perform the operation' }
            }
            Export-ModuleMember -Function Get-ADUser, Set-ADUser
        } | Import-Module -Global

        $adResults = @(Set-ADOUEstonianIDMapping -DN 'OU=Test,DC=example,DC=com' -EstonianIDPropertyName isikukood -UseCache -Replace -Confirm:$false)
        $okRow   = $adResults | Where-Object { $_.Account -eq 'ok.user' }
        $failRow = $adResults | Where-Object { $_.Account -eq 'fail.user' }

        if (-not $okRow -or -not $okRow.Replaced -or $okRow.UpdateError -or $okRow.LookupError) {
            throw "Expected ok.user to be Replaced with no errors, got: $($okRow | Out-String)"
        }
        if (-not $failRow -or $failRow.Replaced -or $failRow.UpdateError -notmatch 'Insufficient access') {
            throw "Expected fail.user Replaced=False with UpdateError set, got: $($failRow | Out-String)"
        }
        Write-Host " PASS: Failed Set-ADUser reported as Replaced=False with UpdateError; batch continued." -ForegroundColor Green

        # Single-user cmdlet: a failed Set-ADUser must surface as an error, in both Replace and Add mode
        foreach ($mode in @{ Replace = $true }, @{}) {
            $modeName = if ($mode.Replace) { 'Replace' } else { 'Add' }
            $ev = $null
            Set-ADUserEstonianIDMapping -Identity 'fail.user' -EstonianID $adTestId -UseCache -Confirm:$false @mode `
                -ErrorAction SilentlyContinue -ErrorVariable ev
            if (-not @($ev | Where-Object { "$_" -match 'was NOT modified.*Insufficient access' })) {
                throw "$modeName mode: expected a 'was NOT modified' error for fail.user, got: $($ev -join '; ')"
            }
            $ev = $null
            Set-ADUserEstonianIDMapping -Identity 'ok.user' -EstonianID $adTestId -UseCache -Confirm:$false @mode `
                -ErrorAction SilentlyContinue -ErrorVariable ev
            if ($ev) {
                throw "$modeName mode: expected no error for ok.user, got: $($ev -join '; ')"
            }
        }
        Write-Host " PASS: Set-ADUserEstonianIDMapping reports failed Set-ADUser as an error (Replace and Add)." -ForegroundColor Green
    }
    finally {
        Remove-Module -Name ActiveDirectory -ErrorAction SilentlyContinue
        if ($adCacheBackup) {
            Set-Content -LiteralPath $adCacheFile -Value $adCacheBackup -Encoding utf8 -NoNewline
        }
        else {
            Remove-Item -LiteralPath $adCacheFile -ErrorAction SilentlyContinue
        }
        Set-TestLdapServer
    }
}

# 11. Recipient certificate validation (cache contents, validity period, curve)
Write-Host "`n[11/13] Testing recipient certificate validation..."
$poisonId = '00000000003'
$poisonFile = Join-Path -Path (& (Get-Module NPU-EstonianID) { $script:CacheFolder }) -ChildPath "$poisonId.json"
try {
    # A cache entry holding someone else's certificate must be ignored, not used for encryption
    $null = New-Item -ItemType Directory -Path (Split-Path -Path $poisonFile) -Force
    @{
        Timestamp   = [DateTime]::UtcNow.ToString('o')
        Base64Certs = @([Convert]::ToBase64String([System.IO.File]::ReadAllBytes($cert2025Path)))
    } | ConvertTo-Json | Set-Content -LiteralPath $poisonFile -Encoding utf8
    Set-TestLdapServer -SK '127.0.0.1' -SKPort 1 -Zetes '127.0.0.1' -ZetesPort 1

    $wv = $null
    $poisonCerts = @(Get-EstEIDCertificate -ID $poisonId -UseCache -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -WarningVariable wv)
    if ($poisonCerts.Count -ne 0) {
        throw "A cached certificate of another person was returned for ID '$poisonId'"
    }
    if (-not @($wv | Where-Object { "$_" -match "Ignoring cached certificate.*PNOEE-$poisonId" })) {
        throw "Expected a warning about the ignored cache entry, got: $($wv -join '; ')"
    }
    Write-Host " PASS: Cache entry holding another person's certificate was ignored." -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $poisonFile -ErrorAction SilentlyContinue
    Set-TestLdapServer
}

$sha384 = [System.Security.Cryptography.HashAlgorithmName]::SHA384
$expiredCert = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=Expired',
    [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP384')), $sha384
).CreateSelfSigned([DateTimeOffset]::Now.AddDays(-10), [DateTimeOffset]::Now.AddDays(-1))
$p256Cert = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=P256',
    [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP256')), $sha384
).CreateSelfSigned([DateTimeOffset]::Now.AddDays(-1), [DateTimeOffset]::Now.AddDays(1))

$rejectOut = Join-Path -Path $env:TEMP -ChildPath 'npu_test_reject.cdoc'
foreach ($case in @{ Cert = $expiredCert; Expect = 'only valid from' }, @{ Cert = $p256Cert; Expect = 'NIST P-384' }) {
    if (Test-Path -LiteralPath $rejectOut) { Remove-Item -LiteralPath $rejectOut -Force }
    $rejectMsg = $null
    try {
        Protect-Cdoc -InputString 'x' -Out $rejectOut -Certificate $case.Cert -ErrorAction Stop
    }
    catch {
        $rejectMsg = $_.Exception.Message
    }
    if ($rejectMsg -notmatch $case.Expect) {
        throw "Expected Protect-Cdoc to reject '$($case.Cert.Subject)' with '$($case.Expect)', got: '$rejectMsg'"
    }
    if (Test-Path -LiteralPath $rejectOut) {
        throw "Output file was created for rejected certificate '$($case.Cert.Subject)'"
    }
}
Write-Host " PASS: Expired and non-P-384 recipient certificates are rejected." -ForegroundColor Green

# Get-EstEIDCertificate -OutFolder saves certificates to files (cached certificate, no network)
$saveId = '60001019906'
$saveCacheFile = Join-Path -Path (& (Get-Module NPU-EstonianID) { $script:CacheFolder }) -ChildPath "$saveId.json"
$saveCacheBackup = if (Test-Path -LiteralPath $saveCacheFile) { Get-Content -LiteralPath $saveCacheFile -Raw }
$saveDir = Join-Path -Path $env:TEMP -ChildPath ("npu_test_save_" + [guid]::NewGuid().ToString('N'))
try {
    @{
        Timestamp   = [DateTime]::UtcNow.ToString('o')
        Base64Certs = @([Convert]::ToBase64String([System.IO.File]::ReadAllBytes($cert2025Path)))
    } | ConvertTo-Json | Set-Content -LiteralPath $saveCacheFile -Encoding utf8
    Set-TestLdapServer -SK '127.0.0.1' -SKPort 1 -Zetes '127.0.0.1' -ZetesPort 1

    $saved = @(Get-EstEIDCertificate -ID $saveId -UseCache -OutFolder $saveDir -ErrorAction Stop)
    $expectedFile = Join-Path -Path $saveDir -ChildPath "cert_${saveId}_$($cert2025.SerialNumber).cer"
    if ($saved.Count -ne 1 -or $saved[0] -isnot [System.IO.FileInfo] -or $saved[0].FullName -ne $expectedFile) {
        throw "Expected one FileInfo for '$expectedFile', got: $($saved | Out-String)"
    }
    $savedCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($expectedFile)
    if ($savedCert.Thumbprint -ne $cert2025.Thumbprint) {
        throw "Saved certificate does not match the cached one"
    }
    Write-Host " PASS: Get-EstEIDCertificate -OutFolder saved the certificate as '$($saved[0].Name)'." -ForegroundColor Green
}
finally {
    if ($saveCacheBackup) {
        Set-Content -LiteralPath $saveCacheFile -Value $saveCacheBackup -Encoding utf8 -NoNewline
    }
    else {
        Remove-Item -LiteralPath $saveCacheFile -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $saveDir -Recurse -Force -ErrorAction SilentlyContinue
    Set-TestLdapServer
}

# 12. Help: every exported command documents itself for Get-Help
Write-Host "`n[12/13] Testing help texts..."
foreach ($name in (Get-Module NPU-EstonianID).ExportedFunctions.Keys) {
    $help = Get-Help $name -Full
    if (-not $help.Synopsis -or $help.Synopsis.Trim() -like "$name *" -or $help.Synopsis.Trim() -eq $name) { throw "$name has no written synopsis" }
    if (-not (($help.description | ForEach-Object { $_.Text }) -join '').Trim()) { throw "$name has no description" }
    if (@($help.examples.example | Where-Object { $_.code }).Count -lt 1) { throw "$name has no example" }
    if (-not $help.returnValues.returnValue) { throw "$name has no .OUTPUTS section" }
    foreach ($p in @($help.parameters.parameter | Where-Object { $_.name -notin 'WhatIf', 'Confirm' })) {
        if (-not (($p.description | ForEach-Object { $_.Text }) -join '').Trim()) { throw "$name does not document -$($p.name)" }
    }
}
Write-Host " PASS: Every exported command has a synopsis, description, examples, outputs and documented parameters." -ForegroundColor Green

# 13. PSScriptAnalyzer: no findings with the repository settings (default rules + PowerShell 5.1/7 compatibility)
Write-Host "`n[13/13] Running PSScriptAnalyzer..."
if (Get-Module -ListAvailable -Name PSScriptAnalyzer) {
    $moduleFolder = Join-Path -Path $PSScriptRoot -ChildPath '..\NPU-EstonianID'
    # PSScriptAnalyzer 1.25 fails on one file of the first multi-file run in a process; warm it up on a single file
    $null = Invoke-ScriptAnalyzer -Path (Join-Path -Path $moduleFolder -ChildPath 'NPU-EstonianID.psm1') -ErrorAction SilentlyContinue
    $analyzerErrors = $null
    $findings = @(Invoke-ScriptAnalyzer -Path $moduleFolder -Recurse -Settings (Join-Path -Path $PSScriptRoot -ChildPath '..\PSScriptAnalyzerSettings.psd1') -ErrorAction SilentlyContinue -ErrorVariable analyzerErrors)
    if (@($analyzerErrors).Count) { throw "PSScriptAnalyzer could not analyze: $(@($analyzerErrors | ForEach-Object { "$($_.TargetObject): $_" }) -join '; ')" }
    if ($findings.Count) { throw "PSScriptAnalyzer findings:`n$(($findings | ForEach-Object { "$($_.ScriptName):$($_.Line) $($_.RuleName): $($_.Message)" }) -join "`n")" }
    Write-Host " PASS: PSScriptAnalyzer: no findings (default rules, PowerShell 5.1 and 7 compatibility)." -ForegroundColor Green
}
else {
    Write-Host " SKIP: PSScriptAnalyzer is not installed for this PowerShell version" -ForegroundColor Yellow
}

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host " ALL TESTS PASSED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
