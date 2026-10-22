# PSScriptAnalyzer settings for NPU-EstonianID:
#   Invoke-ScriptAnalyzer -Path .\NPU-EstonianID -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
# Runs the default rules plus the compatibility rules for the PowerShell versions the module supports.
# Intentional exceptions are suppressed in the code itself, next to the line, with a justification.
@{
    IncludeDefaultRules = $true
    Rules = @{
        PSUseCompatibleSyntax = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
        PSUseCompatibleCommands = @{
            Enable         = $true
            TargetProfiles = @(
                'win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework'  # Windows 10, Windows PowerShell 5.1
                'win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework'   # Windows Server 2019, Windows PowerShell 5.1
                'win-8_x64_10.0.17763.0_7.0.0_x64_3.1.2_core'                          # Windows Server 2019, PowerShell 7
            )
        }
        PSUseCompatibleTypes = @{
            Enable         = $true
            TargetProfiles = @(
                'win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework'
                'win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework'
                'win-8_x64_10.0.17763.0_7.0.0_x64_3.1.2_core'
            )
        }
    }
}
