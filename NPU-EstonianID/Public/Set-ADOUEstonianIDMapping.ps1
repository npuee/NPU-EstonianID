function Set-ADOUEstonianIDMapping {
    <#
    .SYNOPSIS
    Batch updates Estonian ID certificate mappings for active Active Directory users in an Organizational Unit (OU).

    .DESCRIPTION
    Scans enabled users in an OU, reads the personal identification code from the specified attribute,
    resolves certificates from LDAP, and updates user altSecurityIdentities. Emits structured PSCustomObject
    results to the pipeline. Supports native -WhatIf and -Confirm.

    .PARAMETER DN
    DistinguishedName of the Active Directory Organizational Unit (e.g. "OU=Users,DC=example,DC=com").

    .PARAMETER EstonianIDPropertyName
    Active Directory user attribute name where the personal code is stored (e.g. "isikukood").

    .PARAMETER Replace
    Replace existing altSecurityIdentities rather than appending.

    .PARAMETER Force
    With -Replace, update even if the existing mappings already match.
    Has no effect without -Replace, since only missing mappings are ever added.

    .PARAMETER UseCache
    Enables local caching to avoid LDAP rate limits during bulk queries.

    .PARAMETER Sleep
    Optional delay in seconds between processing each user account.

    .EXAMPLE
    Set-ADOUEstonianIDMapping -DN "OU=Employees,DC=corp,DC=local" -EstonianIDPropertyName "isikukood" -WhatIf

    .EXAMPLE
    Set-ADOUEstonianIDMapping -DN "OU=Employees,DC=corp,DC=local" -EstonianIDPropertyName "isikukood" -Replace | Format-Table
    .OUTPUTS
    PSCustomObject per enabled user in the OU: Account, NationalID, MappingExists, CanBeReplaced, NeedsToBeReplaced, Replaced, LookupError, UpdateError.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$DN,

        [Parameter(Mandatory = $true, Position = 1)]
        [string]$EstonianIDPropertyName,

        [Parameter()]
        [switch]$Replace,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$UseCache,

        [Parameter()]
        [int]$Sleep = 0
    )

    process {
        _assertActiveDirectoryModule

        $users = Get-ADUser -Filter 'enabled -eq $true' -SearchBase $DN -Properties $EstonianIDPropertyName, altSecurityIdentities
        foreach ($user in $users) {
            $samAccountName    = $user.SamAccountName
            $nationalID        = $user.$EstonianIDPropertyName
            $existingMappings  = @($user.altSecurityIdentities)
            $newMappings       = @()
            $mappingExists     = $false
            $canBeReplaced     = $false
            $needsToBeReplaced = $false
            $replaced          = $false
            $lookupError       = $null
            $updateError       = $null

            if ($nationalID -and $nationalID -match '^\d{11}$') {
                try {
                    $newMappings = @(Get-IDUserMapping -EstonianID $nationalID -UseCache:$UseCache -ErrorAction Stop)
                }
                catch {
                    $lookupError = $_.Exception.Message
                    $newMappings = @()
                }

                if (-not $lookupError -and $newMappings.Count -gt 0) {
                    $canBeReplaced = $true

                    if ($Replace) {
                        # In Replace mode, mappingExists is true ONLY if existing mappings match new mappings identically
                        $mappingExists = _testIdenticalMappings -MappingsA $existingMappings -MappingsB $newMappings
                        $needsToBeReplaced = (-not $mappingExists)
                    }
                    else {
                        # In Add mode, mappingExists is true if all new mappings are already present in existing
                        $toAdd = @($newMappings | Where-Object { $existingMappings -notcontains $_.Trim() })
                        $mappingExists = ($toAdd.Count -eq 0)
                        $needsToBeReplaced = (-not $mappingExists)
                    }
                }
            }

            # Determine whether to modify
            $shouldModify = (-not $lookupError -and ($needsToBeReplaced -or ($canBeReplaced -and $Force)))

            if ($shouldModify) {
                # Pass the ADUser object (not samAccountName) so the exact account found in the OU is modified.
                # -ErrorAction Stop: Set-ADUser errors are non-terminating by default, which would report Replaced = $true on failure.
                try {
                    if ($Replace) {
                        $targetDesc = "Replace mappings for $samAccountName ($($newMappings.Count) mapping(s))"
                        if ($PSCmdlet.ShouldProcess("ADUser: $samAccountName", $targetDesc)) {
                            Set-ADUser -Identity $user -Replace @{ altSecurityIdentities = [string[]]$newMappings } -ErrorAction Stop
                            $replaced = $true
                        }
                    }
                    else {
                        $toAdd = @($newMappings | Where-Object { $existingMappings -notcontains $_.Trim() })
                        if ($toAdd.Count -gt 0) {
                            $targetDesc = "Add $($toAdd.Count) mapping(s) for $samAccountName"
                            if ($PSCmdlet.ShouldProcess("ADUser: $samAccountName", $targetDesc)) {
                                Set-ADUser -Identity $user -Add @{ altSecurityIdentities = [string[]]$toAdd } -ErrorAction Stop
                                $replaced = $true
                            }
                        }
                    }
                }
                catch {
                    $updateError = $_.Exception.Message
                }
            }

            [PSCustomObject]@{
                Account           = $samAccountName
                NationalID        = $nationalID
                MappingExists     = $mappingExists
                CanBeReplaced     = $canBeReplaced
                NeedsToBeReplaced = $needsToBeReplaced
                Replaced          = $replaced
                LookupError       = $lookupError
                UpdateError       = $updateError
            }

            if ($Sleep -gt 0) {
                Start-Sleep -Seconds $Sleep
            }
        }
    }
}
