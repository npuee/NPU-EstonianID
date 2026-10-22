function Get-ADUserEstonianIDMapping {
    <#
    .SYNOPSIS
    Retrieves altSecurityIdentities attribute values from an Active Directory user account.

    .DESCRIPTION
    Queries Active Directory for the specified user identity and returns the altSecurityIdentities attribute.

    .PARAMETER Identity
    The Active Directory user account (samAccountName, DistinguishedName, SID, or UserPrincipalName). Accepts pipeline input.

    .EXAMPLE
    Get-ADUserEstonianIDMapping -Identity jjoeorg

    .EXAMPLE
    Get-ADUser -Filter 'department -eq "Finance"' | Get-ADUserEstonianIDMapping
    .OUTPUTS
    System.String. The values of the account's altSecurityIdentities attribute.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, Position = 0)]
        [string]$Identity
    )

    process {
        _assertActiveDirectoryModule
        $userProperties = Get-ADUser -Identity $Identity -Properties altSecurityIdentities
        return $userProperties.altSecurityIdentities
    }
}
