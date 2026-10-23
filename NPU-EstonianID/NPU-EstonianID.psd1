@{
    RootModule = 'NPU-EstonianID.psm1'
    ModuleVersion = '1.1.0'
    GUID = '5699d10f-3195-4da4-9239-704ff0e42bbb'
    Author = 'NPU'
    CompanyName = 'NPU'
    Copyright = '(c) NPU. Licensed under the Apache License 2.0.'
    Description = 'Unified Estonian ID card Active Directory management and pure-native CDOC 1.0 container encryption for Windows PowerShell 5.1 and PowerShell 7+.'
    PowerShellVersion = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    # Soft dependency: ActiveDirectory module is not required in manifest
    # allowing non-domain workstations to freely use CDOC encryption and LDAP lookups.
    RequiredModules = @()

    FunctionsToExport = @(
        'Get-EstEIDCertificate',
        'Get-IDUserMapping',
        'Get-ADUserEstonianIDMapping',
        'Set-ADUserEstonianIDMapping',
        'Set-ADOUEstonianIDMapping',
        'Protect-Cdoc'
    )

    CmdletsToExport = @()
    VariablesToExport = @()
    AliasesToExport = @(
        'Protect-File'
    )

    PrivateData = @{
        PSData = @{
            Tags = @('EstonianID', 'EstEID', 'ActiveDirectory', 'CDOC', 'DigiDoc', 'Encryption', 'Security')
            LicenseUri = 'https://github.com/npuee/NPU-EstonianID/blob/main/LICENSE'
            ProjectUri = 'https://github.com/npuee/NPU-EstonianID'
            ReleaseNotes = @'
1.1.0 - First release. Replaces NPU-EstonianIDCard 1.2.0 (deprecated).
- Drop-in replacement for NPU-EstonianIDCard: Get-IDUserMapping, Get-ADUserEstonianIDMapping,
  Set-ADUserEstonianIDMapping and Set-ADOUEstonianIDMapping keep their names, parameters and output.
- New: Protect-Cdoc (alias Protect-File) encrypts files, strings and piped text into CDOC 1.0
  containers that open in DigiDoc4, in pure PowerShell with no external binaries.
- New: Get-EstEIDCertificate returns ID card and Digi-ID certificates (-CardType, -Raw, -OutFolder).
- Lookups search SK ID Solutions first and Zetes only when SK has no ID card for the person.
- The -UseCache certificate cache moved to %LOCALAPPDATA%\NPU-EstonianID\CertCache; cached and
  LDAP certificates are used only if valid and issued to the requested personal code.
- Works on Windows PowerShell 5.1 and PowerShell 7+; Active Directory (RSAT) is needed only for the AD commands.
'@
        }
    }
}
