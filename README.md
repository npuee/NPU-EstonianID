# NPU-EstonianID

Unified PowerShell module for **Estonian ID Card (EstEID)** Active Directory Smart Card authentication management and **pure-native CDOC 1.0 container encryption**.

Built for vanilla **Windows PowerShell 5.1** and **PowerShell 7+** with no external binaries or C++ toolchain.

---

## Highlights

- **Pure Native Cryptography:** Eliminates the ~12 MB C++ `cdoc-tool.exe` binary and OpenSSL/libxml2 dependencies. Uses Windows CNG (`bcrypt.dll`) and .NET cryptographic primitives natively supported on all modern Windows installations.
- **No Plaintext Temporary Files:** Key agreement and AES encryption happen in memory; only the finished encrypted container is written to disk. The certificate cache (below) does store public certificates on disk.
- **Card Generation Agnostic:** Tested and verified with both **2018 SK ID Solutions** cards (ECC NIST P-384, ESTEID2018) and **2025 Zetes** cards (ECC NIST P-384, ESTEID2025). Resolves the upstream OpenSSL RDN index bug on 2025 cards.
- **Cross-Edition Compatibility:** Works seamlessly out-of-the-box on default Windows 10/11 Windows PowerShell 5.1 (`Desktop`) and modern PowerShell 7+ (`Core`).
- **Soft Active Directory Dependency:** Encryption and LDAP certificate lookups can be run on any standalone machine or workstation. Active Directory cmdlets only require RSAT when explicitly called.
- **Fail-Safe LDAP Resolution:** Queries both SK ID Solutions (`esteid.ldap.sk.ee:636`) and Zetes (`ldap.eidpki.ee:636`). If any directory is unreachable, lookups fail loudly instead of returning partial results, preventing accidental deletion of valid logon mappings or incomplete encryption.
- **Dual-Tier LDAP Caching (v2):** 24-hour in-memory and disk cache (`%LOCALAPPDATA%\NPU-EstonianID\CertCache`) to stay safely below Zetes rate limits (60 req/hr), caching only complete query results. Certificates from the cache and from LDAP are only used if they are currently valid and their subject is `PNOEE-<personal code>`.

---

## Installation

Clone the repository or copy the `NPU-EstonianID` module folder into your PowerShell module path:

```powershell
# User module directory
$modulePath = Join-Path -Path ([Environment]::GetFolderPath('MyDocuments')) -ChildPath 'WindowsPowerShell\Modules\NPU-EstonianID'
# Or in PowerShell 7:
# $modulePath = Join-Path -Path ([Environment]::GetFolderPath('MyDocuments')) -ChildPath 'PowerShell\Modules\NPU-EstonianID'

Copy-Item -Path .\NPU-EstonianID -Destination $modulePath -Recurse -Force
Import-Module NPU-EstonianID
```

> **Constrained Language Mode:** the module requires `FullLanguage` mode (it uses `Add-Type` and .NET methods). On systems where AppLocker or WDAC enforce Constrained Language Mode, deploy a copy signed by a publisher trusted by that policy; otherwise `Import-Module` fails with an explanatory error.

---

## Cmdlet Overview

| Cmdlet | Description |
| :--- | :--- |
| `Protect-Cdoc` | Encrypts files or in-memory strings into standard CDOC 1.0 (`ENCDOC-XML\|1.1`) containers decryptable by DigiDoc4. |
| `Get-EstEIDCertificate` | Resolves authentication certificates for 11-digit personal codes from SK or Zetes LDAP directories, optionally saving them as `.cer` files. |
| `Get-IDUserMapping` | Formats certificates or personal codes into Active Directory `X509:<I>...<SR>...` strong name mapping strings. |
| `Get-ADUserEstonianIDMapping` | Reads the current Estonian ID card mappings configured on an Active Directory user account. |
| `Set-ADUserEstonianIDMapping` | Configures an AD user's `altSecurityIdentities` with strong name mappings, with write-suppression if already matching. |
| `Set-ADOUEstonianIDMapping` | Batch processes an entire Organizational Unit (OU), matching AD users with EstEID certificates. |

---

## Usage Examples

### 1. Encrypting Files (CDOC 1.0)

Encrypt a confidential file for an Estonian personal code:

```powershell
Protect-Cdoc -InputFile "C:\Docs\FinancialReport.pdf" -ID 38001085718
# Creates C:\Docs\FinancialReport.pdf.cdoc
```

Multi-recipient encryption (supports multiple 11-digit personal codes):

```powershell
Protect-Cdoc -InputFile "C:\Docs\Contract.docx" -Out "C:\Shared\Contract.cdoc" -ID '38001085718', '60001019906'
```

Pipeline batch file encryption:

```powershell
Get-ChildItem C:\Confidential\*.xlsx | Protect-Cdoc -ID '60001019906' -Out C:\Encrypted\
```

### 2. Encrypting In-Memory Strings (Zero Disk Plaintext)

Encrypt sensitive credentials or API keys directly from memory without writing unencrypted data to disk:

```powershell
"TopSecretDatabasePassword" | Protect-Cdoc -FileName "db_creds.txt" -Out "C:\Vault\db_creds.cdoc" -ID 60001019906
```

Piped lines are joined into a single document. Without `-FileName`/`-Out` the document is named `pipe.txt` and the container `pipe.cdoc` in the current directory:

```powershell
Get-Content .\handover-notes.txt | Protect-Cdoc -ID 60001019906
# Creates .\pipe.cdoc containing pipe.txt
```

Using an in-memory certificate object directly:

```powershell
$cert = Get-EstEIDCertificate -PersonalCode 60001019906
Protect-Cdoc -InputString "System Recovery Token" -Certificate $cert -Out "recovery.cdoc"
```

### 3. Resolving EstEID Certificates

Fetch the active authentication certificate for an Estonian resident:

```powershell
# Returns an in-memory System.Security.Cryptography.X509Certificates.X509Certificate2 object
$cert = Get-EstEIDCertificate -PersonalCode 60001019906

# Inspect certificate details
$cert.Subject
$cert.Thumbprint
$cert.NotAfter

# Save the certificate(s) as cert_<ID>_<SerialNumber>.cer files; returns the saved files
Get-EstEIDCertificate -PersonalCode 60001019906 -OutFolder C:\Certs
```

### 4. Active Directory Smart Card Logon Mappings

Generate the strong certificate mapping string:

```powershell
Get-IDUserMapping -EstonianID 38001085718
# Output (issuer in reversed RDN order, certificate serial number as byte-reversed hex):
# X509:<I>C=EE,O=SK ID Solutions AS,OID.2.5.4.97=NTREE-10747013,CN=ESTEID2018<SR><reversed serial number>
```

Set Smart Card mapping on an Active Directory user account (by default missing mappings are added; `-Replace` overwrites the **whole** `altSecurityIdentities` attribute, including mappings for other smart cards):

```powershell
Set-ADUserEstonianIDMapping -Identity "jjoeorg" -EstonianID "60001019906"
```

Preview changes across an Organizational Unit:

```powershell
Set-ADOUEstonianIDMapping -DN "OU=Staff,DC=corp,DC=example,DC=com" -EstonianIDPropertyName isikukood -WhatIf
```

Emitted output includes `Account`, `NationalID`, `MappingExists`, `CanBeReplaced`, `NeedsToBeReplaced`, `Replaced`, `LookupError` (per-user LDAP lookup failure; the user is skipped) and `UpdateError` (per-user `Set-ADUser` failure; `Replaced` stays `$false`).

---

## Technical Specifications

- **Container Specification:** CDOC 1.0 (`ENCDOC-XML|1.1`)
- **Symmetric Cipher:** AES-256-GCM (12-byte IV, 16-byte authentication tag)
- **Key Agreement:** ECDH-ES on curve NIST P-384 (`urn:oid:1.3.132.0.34` / `secp384r1`)
- **Key Derivation:** ConcatKDF with SHA-384 (NIST SP 800-56A / ANSI X9.63)
- **Key Wrap:** RFC 3394 AES Key Wrap (256-bit KEK wrapping 256-bit transport key -> 40 bytes)
- **Active Directory Mapping:** `X509:<I>...<SR>...` with reverse-ordered RDN and hex serial number complying with Microsoft KB5014754 strong mapping requirements.

---

## Limitations

- **CDOC 1.0 metadata is not encrypted.** The container shows the original file name and size, and each recipient's name and personal code (the `Recipient` attribute and the embedded certificate), to anyone who has the file. DigiDoc4 has created CDOC 2.0 by default since autumn 2026; CDOC 1.0 encryption is supported only temporarily, and no end date has been announced for CDOC 1.0 decryption.
- **Files are encrypted in memory.** The whole file and several encoded copies of it are held in memory at once, so files larger than a few hundred MB may fail.
- **Existing output files are overwritten** without a prompt.
- **`Protect-Cdoc` uses the certificate cache by default**; pass `-NoCache` to always query LDAP. The cache files are named after the personal codes looked up and are not cleaned up automatically.
- **Certificates are not chain-validated.** Certificates from LDAP and the cache are checked for the personal code and validity period, not against the ESTEID2018/ESTEID2025 issuing CAs.

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
