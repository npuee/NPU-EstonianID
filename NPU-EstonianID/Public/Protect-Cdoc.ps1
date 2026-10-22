#
# NPU-EstonianID - Native CDOC 1.0 Container Encryption (PS 5.1 & PS 7+)
#

function Protect-Cdoc {
    <#
    .SYNOPSIS
        Encrypts files or strings into a CDOC 1.0 container using Estonian ID card recipient certificates.
    .DESCRIPTION
        Natively encrypts data using pure .NET and Windows CNG (bcrypt.dll) with zero external binaries
        or temporary files. Recipient certificates are resolved in-memory from LDAP (SK or Zetes) or passed
        as X509Certificate2 objects. Produces standard CDOC 1.0 containers (ENCDOC-XML|1.1, AES-256-GCM,
        ECDH-ES NIST P-384, ConcatKDF SHA-384, RFC 3394 AES-KW) fully decryptable in DigiDoc4 Client.
    .PARAMETER InputFile
        Path to the file to encrypt. Accepts file objects from the pipeline (e.g. Get-ChildItem) by property name
        (FullName, PSPath, Path). Plain strings piped in are treated as -InputString text, not as paths.
    .PARAMETER InputString
        String content to encrypt directly in memory. When several strings are piped in
        (e.g. from Get-Content), they are joined with newlines into a single document.
    .PARAMETER FileName
        Name of the file entry inside the CDOC container when encrypting an InputString. Defaults to 'pipe.txt'.
    .PARAMETER Out
        Destination path for the .cdoc file.
        If omitted in file mode, defaults to '<InputFile>.cdoc'; in string mode, to '<FileName without extension>.cdoc'
        in the current directory (e.g. 'pipe.cdoc').
        If pointing to an existing directory, the same default name is used inside it.
    .PARAMETER ID
        One or more 11-digit Estonian personal codes (e.g. '38001085718', '60001019906').
        Certificates are looked up in-memory via LDAP and cached locally.
    .PARAMETER Certificate
        One or more X509Certificate2 objects or certificate byte arrays representing recipient public certificates.
    .PARAMETER PassThru
        Returns the created FileInfo object for the generated .cdoc container.
    .EXAMPLE
        Protect-Cdoc -InputFile C:\Docs\Contract.pdf -ID 38001085718
        Encrypts Contract.pdf for personal code 38001085718, creating Contract.pdf.cdoc.
    .EXAMPLE
        Get-ChildItem C:\Confidential\*.xlsx | Protect-Cdoc -ID '38001085718', '60001019906' -Out C:\Encrypted\
        Encrypts multiple files for two recipients in batch.
    .EXAMPLE
        Protect-Cdoc -InputString "Confidential password" -FileName "creds.txt" -Out "C:\creds.cdoc" -ID 60001019906
        Encrypts in-memory text directly without ever touching disk with plaintext.
    .EXAMPLE
        $cert = Get-EstEIDCertificate -PersonalCode 60001019906
        Protect-Cdoc -InputFile secret.docx -Certificate $cert
        Encrypts using an in-memory certificate object directly.
    #>
    # InputFile and InputString deliberately share one parameter set (like Set-Content's -Path/-Value):
    # with two sets the binder commits to the default set before pipeline input arrives, so piped
    # strings could never reach -InputString. Piped FileInfo objects bind to InputFile by property name.
    [CmdletBinding()]
    [Alias('Protect-File')]
    param(
        [Parameter(Position = 0, ValueFromPipelineByPropertyName = $true)]
        [Alias('In', 'FullName', 'PSPath', 'Path')]
        [string]$InputFile,

        [Parameter(ValueFromPipeline = $true)]
        [AllowEmptyString()]
        [Alias('Content', 'String')]
        [string]$InputString,

        [Parameter(Mandatory = $false)]
        [string]$FileName = "pipe.txt",

        [Parameter(Mandatory = $false, Position = 1)]
        [Alias('OutputPath', 'Destination')]
        [string]$Out,

        [Parameter(Mandatory = $false)]
        [ValidatePattern('^\d{11}$')]
        [Alias('PersonalCode', 'Isikukood')]
        [string[]]$ID,

        [Parameter(Mandatory = $false)]
        [Alias('Cert')]
        [object[]]$Certificate,

        [Parameter()]
        [switch]$PassThru,

        [Parameter()]
        [switch]$NoCache
    )

    begin {
        if (-not $ID -and -not $Certificate) {
            throw "At least one recipient must be specified via -ID (11-digit personal code) or -Certificate (X509Certificate2 object)."
        }
        # Piped strings are collected and encrypted as one document in the end block
        $stringParts = [System.Collections.Generic.List[string]]::new()
        $fileCount = 0
    }

    process {
        # A piped FileInfo also binds (coerced) to InputString, so a non-empty InputFile always wins.
        # Pipeline-bound values are reset for every input object; bound keys are not, so check values first.
        if ([string]::IsNullOrEmpty($InputFile)) {
            if ($PSBoundParameters.ContainsKey('InputString')) {
                $stringParts.Add($InputString)
            }
            return
        }
        if ($PSBoundParameters.ContainsKey('InputString') -and -not $MyInvocation.ExpectingInput) {
            throw "Specify either -InputFile or -InputString, not both."
        }
        $fileCount++

        $resolvedInputPath = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($InputFile)
        if (-not (Test-Path -LiteralPath $resolvedInputPath -PathType Leaf)) {
            throw "Input file not found: '$resolvedInputPath'"
        }
        $entryName = [System.IO.Path]::GetFileName($resolvedInputPath)
        _Protect-CdocItem -PlaintextBytes ([System.IO.File]::ReadAllBytes($resolvedInputPath)) -EntryName $entryName `
            -DefaultOutName "$entryName.cdoc" -DefaultOutPath "$resolvedInputPath.cdoc"
    }

    end {
        if ($stringParts.Count -eq 0) {
            if ($fileCount -eq 0) {
                throw "No input specified. Provide -InputFile, -InputString, or pipe files or strings into Protect-Cdoc."
            }
            return
        }
        $entryName = if ([string]::IsNullOrWhiteSpace($FileName)) { "pipe.txt" } else { [System.IO.Path]::GetFileName($FileName) }
        $outName = "$([System.IO.Path]::GetFileNameWithoutExtension($entryName)).cdoc"
        $plaintext = $stringParts -join [System.Environment]::NewLine
        _Protect-CdocItem -PlaintextBytes ([System.Text.Encoding]::UTF8.GetBytes($plaintext)) -EntryName $entryName `
            -DefaultOutName $outName -DefaultOutPath (Join-Path -Path (Get-Location).Path -ChildPath $outName)
    }
}

# Encrypts one document for the recipients bound to the calling Protect-Cdoc invocation
# ($Out, $ID, $Certificate, $NoCache, $PassThru and $PSCmdlet are resolved from the caller's scope).
function _Protect-CdocItem {
    param(
        [byte[]]$PlaintextBytes,
        [string]$EntryName,
        [string]$DefaultOutName,
        [string]$DefaultOutPath
    )

    # 2. Determine output file path
    $outPath = $null
    if ([string]::IsNullOrWhiteSpace($Out)) {
        $outPath = $DefaultOutPath
    }
    else {
        $resolvedOut = $PSCmdlet.GetUnresolvedProviderPathFromPSPath($Out)
        if (Test-Path -LiteralPath $resolvedOut -PathType Container) {
            $outPath = Join-Path -Path $resolvedOut -ChildPath $DefaultOutName
        }
        else {
            $outPath = $resolvedOut
        }
    }

    # 3. Resolve recipient certificates
    $recipientCerts = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()

    if ($Certificate) {
        # A single byte[] passed to the [object[]] parameter arrives unrolled into individual bytes
        $certInputs = $Certificate
        if (@($Certificate | Where-Object { $_ -isnot [byte] }).Count -eq 0) {
            $certInputs = , [byte[]]$Certificate
        }
        foreach ($c in $certInputs) {
            if ($c -is [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
                $recipientCerts.Add($c)
            }
            elseif ($c -is [byte[]]) {
                $recipientCerts.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new([byte[]]$c))
            }
            else {
                throw "Invalid certificate object type: $($c.GetType().FullName). Must be X509Certificate2 or byte[]."
            }
        }
    }

    if ($ID) {
        foreach ($code in $ID) {
            Write-Verbose "Resolving certificate for personal code: $code"
            $certs = @(Get-EstEIDCertificate -ID $code -UseCache:(-not $NoCache) -ErrorAction Stop)
            if (-not $certs -or $certs.Count -eq 0) {
                throw "Unable to find an authentication certificate for Estonian personal code '$code'."
            }
            foreach ($c in $certs) {
                $recipientCerts.Add($c)
            }
        }
    }

    # Deduplicate recipient certificates by thumbprint
    $uniqueCerts = @()
    $seenThumbprints = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($c in $recipientCerts) {
        if ($seenThumbprints.Add($c.Thumbprint)) {
            $uniqueCerts += $c
        }
    }

    if ($uniqueCerts.Count -eq 0) {
        throw "No valid recipient certificates could be resolved."
    }

    $now = [DateTime]::Now
    foreach ($c in $uniqueCerts) {
        if ($c.NotBefore -gt $now -or $c.NotAfter -lt $now) {
            throw "Recipient certificate '$($c.Subject)' is only valid from $($c.NotBefore) to $($c.NotAfter); the recipient could not decrypt with it."
        }
    }

    # 4. Generate random 256-bit transport key and 96-bit IV
    $transportKey = [CdocCryptoEngine]::GenerateRandomBytes(32)
    $iv = [CdocCryptoEngine]::GenerateRandomBytes(12)

    try {
        $documentFormat = "ENCDOC-XML|1.1"
        $algoIdBytes = [System.Text.Encoding]::ASCII.GetBytes($documentFormat)
        $recipientList = [System.Collections.Generic.List[PSObject]]::new()

        foreach ($cert in $uniqueCerts) {
            $recipientName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
            if ([string]::IsNullOrWhiteSpace($recipientName)) {
                $recipientName = $cert.Subject
            }

            $isRsa = ($cert.PublicKey.Oid.Value -eq "1.2.840.113549.1.1.1" -or $cert.PublicKey.Oid.FriendlyName -eq "RSA")
            if ($isRsa) {
                Write-Verbose "Performing RSA PKCS#1 v1.5 transport key encryption for recipient: $recipientName"
                $encKey = [CdocCryptoEngine]::EncryptRsaPkcs1($cert, $transportKey)
                $recipientList.Add([PSCustomObject]@{
                    RecipientName    = $recipientName
                    IsRsa            = $true
                    EncryptedKey     = $encKey
                    RecipientCertRaw = $cert.RawData
                })
            }
            else {
                Write-Verbose "Performing ECDH key agreement for recipient: $recipientName"
                $ecdh = [CdocCryptoEngine]::PerformEcdhAgreement($cert)

                # ConcatKDF (NIST SP 800-56A SHA-384) -> 32 bytes KEK
                $kek = [CdocCryptoEngine]::ConcatKdfSha384($ecdh.SharedSecret, $algoIdBytes, $ecdh.EphemeralPublicKeyDer, $cert.RawData, 32)

                # RFC 3394 AES Key Wrap
                $wrappedKey = [CdocCryptoEngine]::AesKeyWrap($kek, $transportKey)

                $recipientList.Add([PSCustomObject]@{
                    RecipientName      = $recipientName
                    IsRsa              = $false
                    WrappedKey         = $wrappedKey
                    EphemeralPublicKey = $ecdh.EphemeralPublicKeyDer
                    RecipientCertRaw   = $cert.RawData
                })
            }
        }

        # 5. Encrypt payload with AES-256-GCM
        Write-Verbose "Encrypting $($plaintextBytes.Length) bytes payload with AES-256-GCM..."
        $encryptedPayload = [CdocCryptoEngine]::EncryptAes256Gcm($transportKey, $iv, $plaintextBytes)

        # 6. Build CDOC 1.0 XML Document
        $xmlDoc = New-Cdoc1XmlContainer -EncryptedPayload $encryptedPayload `
            -FileName $entryName `
            -FileSize $plaintextBytes.Length `
            -Recipients $recipientList `
            -DocumentFormat $documentFormat `
            -LibraryVersion "1.0.0"

        # 7. Write output file
        $outDir = [System.IO.Path]::GetDirectoryName($outPath)
        if (-not [string]::IsNullOrEmpty($outDir) -and -not (Test-Path -LiteralPath $outDir)) {
            $null = New-Item -ItemType Directory -Path $outDir -Force
        }
        [System.IO.File]::WriteAllText($outPath, $xmlDoc, [System.Text.UTF8Encoding]::new($false))
        Write-Verbose "Protected container written to '$outPath'."

        if ($PassThru) {
            Get-Item -LiteralPath $outPath
        }
    }
    finally {
        # Zeroize sensitive transport key from memory
        [System.Array]::Clear($transportKey, 0, $transportKey.Length)
        if ($plaintextBytes) {
            [System.Array]::Clear($plaintextBytes, 0, $plaintextBytes.Length)
        }
    }
}
