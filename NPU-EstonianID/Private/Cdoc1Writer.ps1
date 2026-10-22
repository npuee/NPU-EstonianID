#
# NPU-EstonianID - CDOC 1.0 XML Builder (PS 5.1 & PS 7+)
#

function _newCdoc1XmlContainer {
    <#
    .SYNOPSIS
        Builds the CDOC 1.0 (ENCDOC-XML|1.1) XML structure.
    .DESCRIPTION
        Assembles all cryptographic agreement components and encrypted payload into a
        W3C XML-ENC compliant CDOC 1.0 document recognized by DigiDoc4 Client and libcdoc.
    .PARAMETER EncryptedPayload
        Byte array containing AES-256-GCM ciphertext in format: IV (12B) || Ciphertext (NB) || Tag (16B).
    .PARAMETER FileName
        Original name of the encrypted file.
    .PARAMETER FileSize
        Original uncompressed size of the file in bytes.
    .PARAMETER Recipients
        Collection of recipient key objects with properties:
        RecipientName, WrappedKey, EphemeralPublicKey, RecipientCertRaw.
    .PARAMETER DocumentFormat
        Format identifier, defaults to 'ENCDOC-XML|1.1'.
    .PARAMETER LibraryVersion
        Library version tag, defaults to '1.0.0'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$EncryptedPayload,

        [Parameter(Mandatory = $true)]
        [string]$FileName,

        [Parameter(Mandatory = $true)]
        [long]$FileSize,

        [Parameter(Mandatory = $true)]
        [array]$Recipients,

        [Parameter(Mandatory = $false)]
        [string]$DocumentFormat = "ENCDOC-XML|1.1",

        [Parameter(Mandatory = $false)]
        [string]$LibraryVersion = "1.0.0"
    )

    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.Append("<?xml version=`"1.0`" encoding=`"UTF-8`"?>`r`n")
    $null = $sb.Append("<denc:EncryptedData MimeType=`"application/octet-stream`" xmlns:denc=`"http://www.w3.org/2001/04/xmlenc#`">")
    $null = $sb.Append("<denc:EncryptionMethod Algorithm=`"http://www.w3.org/2009/xmlenc11#aes256-gcm`"/>")
    $null = $sb.Append("<ds:KeyInfo xmlns:ds=`"http://www.w3.org/2000/09/xmldsig#`">")

    # AlgorithmID = "00" + Hex("ENCDOC-XML|1.1")
    $algoIdBytes = [System.Text.Encoding]::ASCII.GetBytes($DocumentFormat)
    $algoIdHex = "00" + [BitConverter]::ToString($algoIdBytes).Replace("-", "")

    foreach ($r in $Recipients) {
        $recipientEscaped = [System.Security.SecurityElement]::Escape($r.RecipientName)
        $certB64 = [Convert]::ToBase64String($r.RecipientCertRaw, [System.Base64FormattingOptions]::InsertLineBreaks)

        if ($r.IsRsa) {
            $encKeyB64 = [Convert]::ToBase64String($r.EncryptedKey)
            $null = $sb.Append("<denc:EncryptedKey Recipient=`"$recipientEscaped`">")
            $null = $sb.Append("<denc:EncryptionMethod Algorithm=`"http://www.w3.org/2001/04/xmlenc#rsa-1_5`"/>")
            $null = $sb.Append("<ds:KeyInfo>")
            $null = $sb.Append("<ds:X509Data>")
            $null = $sb.Append("<ds:X509Certificate>$certB64</ds:X509Certificate>")
            $null = $sb.Append("</ds:X509Data>")
            $null = $sb.Append("</ds:KeyInfo>")
            $null = $sb.Append("<denc:CipherData>")
            $null = $sb.Append("<denc:CipherValue>$encKeyB64</denc:CipherValue>")
            $null = $sb.Append("</denc:CipherData>")
            $null = $sb.Append("</denc:EncryptedKey>")
        }
        else {
            $partyUHex = "00" + [BitConverter]::ToString($r.EphemeralPublicKey).Replace("-", "")
            $partyVHex = "00" + [BitConverter]::ToString($r.RecipientCertRaw).Replace("-", "")

            $ephPubB64 = [Convert]::ToBase64String($r.EphemeralPublicKey, [System.Base64FormattingOptions]::InsertLineBreaks)
            $wrappedKeyB64 = [Convert]::ToBase64String($r.WrappedKey)

            $null = $sb.Append("<denc:EncryptedKey Recipient=`"$recipientEscaped`">")
            $null = $sb.Append("<denc:EncryptionMethod Algorithm=`"http://www.w3.org/2001/04/xmlenc#kw-aes256`"/>")
            $null = $sb.Append("<ds:KeyInfo>")
            $null = $sb.Append("<denc:AgreementMethod Algorithm=`"http://www.w3.org/2009/xmlenc11#ECDH-ES`">")
            $null = $sb.Append("<xenc11:KeyDerivationMethod Algorithm=`"http://www.w3.org/2009/xmlenc11#ConcatKDF`" xmlns:xenc11=`"http://www.w3.org/2009/xmlenc11#`">")
            $null = $sb.Append("<xenc11:ConcatKDFParams PartyVInfo=`"$partyVHex`" AlgorithmID=`"$algoIdHex`" PartyUInfo=`"$partyUHex`">")
            $null = $sb.Append("<ds:DigestMethod Algorithm=`"http://www.w3.org/2001/04/xmlenc#sha384`"/>")
            $null = $sb.Append("</xenc11:ConcatKDFParams>")
            $null = $sb.Append("</xenc11:KeyDerivationMethod>")
            $null = $sb.Append("<denc:OriginatorKeyInfo>")
            $null = $sb.Append("<ds:KeyValue>")
            $null = $sb.Append("<dsig11:ECKeyValue xmlns:dsig11=`"http://www.w3.org/2009/xmldsig11#`">")
            $null = $sb.Append("<dsig11:NamedCurve URI=`"urn:oid:1.3.132.0.34`"/>")
            $null = $sb.Append("<dsig11:PublicKey>$ephPubB64</dsig11:PublicKey>")
            $null = $sb.Append("</dsig11:ECKeyValue>")
            $null = $sb.Append("</ds:KeyValue>")
            $null = $sb.Append("</denc:OriginatorKeyInfo>")
            $null = $sb.Append("<denc:RecipientKeyInfo>")
            $null = $sb.Append("<ds:X509Data>")
            $null = $sb.Append("<ds:X509Certificate>$certB64</ds:X509Certificate>")
            $null = $sb.Append("</ds:X509Data>")
            $null = $sb.Append("</denc:RecipientKeyInfo>")
            $null = $sb.Append("</denc:AgreementMethod>")
            $null = $sb.Append("</ds:KeyInfo>")
            $null = $sb.Append("<denc:CipherData>")
            $null = $sb.Append("<denc:CipherValue>$wrappedKeyB64</denc:CipherValue>")
            $null = $sb.Append("</denc:CipherData>")
            $null = $sb.Append("</denc:EncryptedKey>")
        }
    }

    $null = $sb.Append("</ds:KeyInfo>")

    $payloadB64 = [Convert]::ToBase64String($EncryptedPayload, [System.Base64FormattingOptions]::InsertLineBreaks)
    $null = $sb.Append("<denc:CipherData>")
    $null = $sb.Append("<denc:CipherValue>$payloadB64</denc:CipherValue>")
    $null = $sb.Append("</denc:CipherData>")

    $origFileProp = "$FileName|$FileSize|application/octet-stream|D0"
    $filenameEscaped = [System.Security.SecurityElement]::Escape($FileName)
    $origFileEscaped = [System.Security.SecurityElement]::Escape($origFileProp)
    $libraryVersionEscaped = [System.Security.SecurityElement]::Escape($LibraryVersion)
    $documentFormatEscaped = [System.Security.SecurityElement]::Escape($DocumentFormat)

    $null = $sb.Append("<denc:EncryptionProperties>")
    $null = $sb.Append("<denc:EncryptionProperty Name=`"LibraryVersion`">$libraryVersionEscaped</denc:EncryptionProperty>")
    $null = $sb.Append("<denc:EncryptionProperty Name=`"DocumentFormat`">$documentFormatEscaped</denc:EncryptionProperty>")
    $null = $sb.Append("<denc:EncryptionProperty Name=`"Filename`">$filenameEscaped</denc:EncryptionProperty>")
    $null = $sb.Append("<denc:EncryptionProperty Name=`"orig_file`">$origFileEscaped</denc:EncryptionProperty>")
    $null = $sb.Append("</denc:EncryptionProperties>")
    $null = $sb.Append("</denc:EncryptedData>`r`n")

    return $sb.ToString()
}
