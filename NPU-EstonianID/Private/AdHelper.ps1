#
# Active Directory Soft/Lazy Requirement and Mapping Helpers
#

function _assertActiveDirectoryModule {
    if (-not (Get-Module -Name ActiveDirectory)) {
        try {
            Import-Module -Name ActiveDirectory -ErrorAction Stop
        }
        catch {
            throw "The ActiveDirectory PowerShell module is required for this cmdlet but is not available on this system."
        }
    }
}

function _testIdenticalMappings {
    param(
        [string[]]$MappingsA,
        [string[]]$MappingsB
    )

    $listA = @($MappingsA | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })
    $listB = @($MappingsB | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() })

    if ($listA.Count -ne $listB.Count) {
        return $false
    }

    foreach ($item in $listA) {
        if ($listB -notcontains $item) {
            return $false
        }
    }

    return $true
}

function _formatStrongNameMapping {
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    # Reverse certificate serial (2-byte chunks from big-endian to little-endian representation)
    $serialChars = $Certificate.SerialNumber.ToCharArray()
    $reversedSerial = ""
    for ($i = 0; $i -lt $serialChars.Length; $i += 2) {
        $reversedSerial = $serialChars[$i] + $serialChars[$i + 1] + $reversedSerial
    }

    # Reverse certificate issuer DN components
    $issuerParts = $Certificate.Issuer.Split(",")
    $reversedIssuer = ""
    foreach ($part in $issuerParts) {
        $reversedIssuer = $part + "," + $reversedIssuer
    }
    $reversedIssuer = $reversedIssuer.Replace(', ', ',')
    $reversedIssuer = $reversedIssuer.Substring(0, $reversedIssuer.Length - 1)

    # Strong Name Mapping:
    return "X509:<I>" + $reversedIssuer.Trim() + "<SR>" + $reversedSerial
}
