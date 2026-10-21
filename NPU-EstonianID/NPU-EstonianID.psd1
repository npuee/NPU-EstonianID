@{
    RootModule = 'NPU-EstonianID.psm1'
    ModuleVersion = '1.0.0'
    GUID = '9f8e7d6c-5b4a-4321-b0e1-0123456789ab'
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
            LicenseUri = 'https://github.com/npu/NPU-EstonianID/blob/main/LICENSE'
            ProjectUri = 'https://github.com/npu/NPU-EstonianID'
        }
    }
}
