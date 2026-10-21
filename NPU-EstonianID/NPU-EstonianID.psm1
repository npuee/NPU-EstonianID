#
# NPU-EstonianID - PowerShell Module Root
# Unified Estonian ID Card Active Directory & CDOC Container Management
#

# The module relies on Add-Type and .NET method calls, which Constrained Language Mode blocks.
# A module signed by a publisher trusted by the AppLocker/WDAC policy runs in FullLanguage.
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    throw "NPU-EstonianID requires FullLanguage mode, but the module is running in $($ExecutionContext.SessionState.LanguageMode). On systems enforcing AppLocker or WDAC, install a copy of the module that is signed by a trusted publisher."
}

foreach ($folder in 'Private', 'Public') {
    $files = Get-ChildItem -Path (Join-Path -Path $PSScriptRoot -ChildPath $folder) -Filter '*.ps1'
    foreach ($file in $files) {
        try {
            . $file.FullName
        }
        catch {
            throw "Failed to import $($folder.ToLower()) script '$($file.FullName)': $_"
        }
    }
}

Export-ModuleMember -Function @(
    'Get-EstEIDCertificate',
    'Get-IDUserMapping',
    'Get-ADUserEstonianIDMapping',
    'Set-ADUserEstonianIDMapping',
    'Set-ADOUEstonianIDMapping',
    'Protect-Cdoc'
) -Alias @(
    'Protect-File'
)
