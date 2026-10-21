#
# NPU-EstonianID - Generates the synthetic test certificates used by Run-Tests.ps1
#
# The certificates mimic the structure of real Estonian ID card authentication certificates
# (NIST P-384 keys, SERIALNUMBER=PNOEE-<code>, "SURNAME,GIVENNAME,CODE" common name) but are
# issued by throwaway keys under "TEST of ..." issuer names and use SK's public test identities,
# so the repository contains no real personal data.
#
# The ESTEID2025 (Zetes) issuer is deliberately encoded in reversed RDN order (CN first),
# like real 2025 cards, so the strong-name mapping tests cover both encodings.
#
# Requires PowerShell 7. Run from any directory; writes into the Tests folder.
#

$ErrorActionPreference = 'Stop'
$ec = [System.Security.Cryptography.ECCurve]::CreateFromFriendlyName('nistP384')
$sha384 = [System.Security.Cryptography.HashAlgorithmName]::SHA384

function New-TestCard {
    param([string]$Issuer, [string]$Subject, [string]$FileName)

    $caKey = [System.Security.Cryptography.ECDsa]::Create($ec)
    $userKey = [System.Security.Cryptography.ECDsa]::Create($ec)

    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new($Subject), $userKey, $sha384)
    $req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]'DigitalSignature, KeyAgreement', $true))

    $serial = [byte[]]::new(16)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($serial)
    $serial[0] = $serial[0] -band 0x7F

    $cert = $req.Create(
        [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new($Issuer),
        [System.Security.Cryptography.X509Certificates.X509SignatureGenerator]::CreateForECDsa($caKey),
        [DateTimeOffset]::new(2025, 1, 1, 0, 0, 0, [TimeSpan]::Zero),
        [DateTimeOffset]::new(2045, 1, 1, 0, 0, 0, [TimeSpan]::Zero),
        $serial)

    $path = Join-Path -Path $PSScriptRoot -ChildPath $FileName
    [System.IO.File]::WriteAllBytes($path, $cert.RawData)
    Write-Host "$FileName"
    Write-Host "  Subject: $($cert.Subject)"
    Write-Host "  Issuer : $($cert.Issuer)"
}

New-TestCard -FileName 'cert_esteid2018_test.cer' `
    -Issuer 'CN=TEST of ESTEID2018, OID.2.5.4.97=NTREE-10747013, O=SK ID Solutions AS, C=EE' `
    -Subject 'SERIALNUMBER=PNOEE-38001085718, G=JAAK-KRISTJAN, SN=JÕEORG, CN="JÕEORG,JAAK-KRISTJAN,38001085718", C=EE'

New-TestCard -FileName 'cert_esteid2025_test.cer' `
    -Issuer 'C=EE, O=Zetes Estonia OÜ, OID.2.5.4.97=NTREE-17066049, CN=TEST of ESTEID2025' `
    -Subject 'C=EE, SN=O''CONNEŽ-ŠUSLIK TESTNUMBER, G=MARY ÄNN, SERIALNUMBER=PNOEE-60001019906, CN="O''CONNEŽ-ŠUSLIK TESTNUMBER,MARY ÄNN,60001019906"'
