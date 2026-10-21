function Set-ADUserEstonianIDMapping {
    <#
    .SYNOPSIS
    Sets or adds Estonian ID card certificate mappings to an Active Directory user's altSecurityIdentities.

    .DESCRIPTION
    Resolves an Estonian personal code to certificate mappings via Get-IDUserMapping and updates
    the target Active Directory user account. Supports native -WhatIf and -Confirm.

    .PARAMETER Identity
    Active Directory user account identity. Accepts pipeline input.

    .PARAMETER EstonianID
    11-digit Estonian personal identification code.

    .PARAMETER EstonianIDPropertyName
    Active Directory user attribute name where the Estonian personal code is stored (e.g. 'isikukood').

    .PARAMETER Replace
    If specified, replaces existing altSecurityIdentities with resolved mappings. By default, new mappings are added.

    .PARAMETER Force
    Forces writing to Active Directory even if existing altSecurityIdentities already match.

    .PARAMETER UseCache
    Enables local caching to avoid LDAP rate limits during bulk queries.

    .EXAMPLE
    Set-ADUserEstonianIDMapping -Identity jjoeorg -EstonianID '38001085718' -Replace

    .EXAMPLE
    Set-ADUserEstonianIDMapping -Identity jjoeorg -EstonianIDPropertyName isikukood -WhatIf
    #>
    [CmdletBinding(DefaultParameterSetName = 'EstonianID', SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [Parameter(ParameterSetName = 'EstonianID', Mandatory = $true, Position = 1)]
        [ValidatePattern('^\d{11}$')]
        [string]$EstonianID,

        [Parameter(ParameterSetName = 'EstonianIDPropertyName', Mandatory = $true, Position = 1)]
        [string]$EstonianIDPropertyName,

        [Parameter()]
        [switch]$Replace,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$UseCache,

        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string]$Identity
    )

    process {
        Assert-ActiveDirectoryModule

        $resolvedID = $EstonianID
        $existingMappings = @()

        if ($PSCmdlet.ParameterSetName -eq 'EstonianIDPropertyName') {
            try {
                $user = Get-ADUser -Identity $Identity -Properties $EstonianIDPropertyName, altSecurityIdentities
                $resolvedID = $user.$EstonianIDPropertyName
                $existingMappings = @($user.altSecurityIdentities)
            }
            catch {
                throw "Failed to retrieve attribute '$EstonianIDPropertyName' for user '$Identity': $($_.Exception.Message)"
            }

            if (-not $resolvedID) {
                Write-Warning "User '$Identity' has no value in attribute '$EstonianIDPropertyName'. Skipping."
                return
            }

            if ($resolvedID -notmatch '^\d{11}$') {
                Write-Warning "Attribute '$EstonianIDPropertyName' for user '$Identity' ('$resolvedID') is not an 11-digit numeric ID. Skipping."
                return
            }
        }
        else {
            try {
                $user = Get-ADUser -Identity $Identity -Properties altSecurityIdentities
                $existingMappings = @($user.altSecurityIdentities)
            }
            catch {
                throw "Failed to retrieve user '$Identity' from Active Directory: $($_.Exception.Message)"
            }
        }

        $mappings = $null
        try {
            $mappings = @(Get-IDUserMapping -EstonianID $resolvedID -UseCache:$UseCache -ErrorAction Stop)
        }
        catch {
            Write-Error "LDAP lookup failed for ID '$resolvedID'; user '$Identity' was NOT modified: $($_.Exception.Message)"
            return
        }

        if (-not $mappings -or $mappings.Count -eq 0) {
            Write-Warning "No certificates found in LDAP for ID '$resolvedID'. User '$Identity' was not modified."
            return
        }

        # Avoid unnecessary writes if values are already the same
        if ($Replace) {
            $isIdentical = _Test-IdenticalMappings -MappingsA $existingMappings -MappingsB $mappings
            if ($isIdentical -and -not $Force) {
                Write-Verbose "altSecurityIdentities for user '$Identity' already match the resolved certificate mapping(s). No write required."
                return
            }

            $actionDesc = "Replace altSecurityIdentities with $($mappings.Count) mapping(s)"
            if ($PSCmdlet.ShouldProcess("ADUser: $Identity", $actionDesc)) {
                Set-ADUser -Identity $Identity -Replace @{ altSecurityIdentities = [string[]]$mappings }
                Write-Verbose "Successfully replaced altSecurityIdentities for user '$Identity'."
            }
        }
        else {
            # Add mode: only add mappings not already present
            $toAdd = @($mappings | Where-Object { $existingMappings -notcontains $_.Trim() })
            if ($toAdd.Count -eq 0) {
                Write-Verbose "All resolved certificate mapping(s) already exist in altSecurityIdentities for user '$Identity'. No write required."
                return
            }

            $actionDesc = "Add $($toAdd.Count) mapping(s) to altSecurityIdentities"
            if ($PSCmdlet.ShouldProcess("ADUser: $Identity", $actionDesc)) {
                Set-ADUser -Identity $Identity -Add @{ altSecurityIdentities = [string[]]$toAdd }
                Write-Verbose "Successfully added $($toAdd.Count) mapping(s) to altSecurityIdentities for user '$Identity'."
            }
        }
    }
}
