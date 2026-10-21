#
# NPU-EstonianID - Native Cryptography Engine (PS 5.1 & PS 7+)
#

$script:CdocCryptoDefinition = @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public static class CdocCryptoEngine {
    // -------------------------------------------------------------
    // ConcatKDF (NIST SP 800-56A / ANSI X9.63) with SHA-384
    // -------------------------------------------------------------
    public static byte[] ConcatKdfSha384(byte[] z, byte[] algorithmId, byte[] partyU, byte[] partyV, int keyDataLen) {
        byte[] otherInfo = new byte[algorithmId.Length + partyU.Length + partyV.Length];
        Buffer.BlockCopy(algorithmId, 0, otherInfo, 0, algorithmId.Length);
        Buffer.BlockCopy(partyU, 0, otherInfo, algorithmId.Length, partyU.Length);
        Buffer.BlockCopy(partyV, 0, otherInfo, algorithmId.Length + partyU.Length, partyV.Length);

        using (SHA384 sha = SHA384.Create()) {
            byte[] input = new byte[4 + z.Length + otherInfo.Length];
            input[0] = 0; input[1] = 0; input[2] = 0; input[3] = 1; // Counter = 1
            Buffer.BlockCopy(z, 0, input, 4, z.Length);
            Buffer.BlockCopy(otherInfo, 0, input, 4 + z.Length, otherInfo.Length);

            byte[] hash = sha.ComputeHash(input);
            byte[] key = new byte[keyDataLen];
            Buffer.BlockCopy(hash, 0, key, 0, keyDataLen);
            return key;
        }
    }

    // -------------------------------------------------------------
    // RFC 3394 AES Key Wrap (256-bit KEK, 256-bit plaintext transport key)
    // -------------------------------------------------------------
    public static byte[] AesKeyWrap(byte[] kek, byte[] plaintext) {
        if (plaintext.Length % 8 != 0) throw new ArgumentException("Plaintext must be multiple of 8 bytes");
        int n = plaintext.Length / 8;
        ulong a = 0xA6A6A6A6A6A6A6A6;
        byte[][] r = new byte[n + 1][];
        for (int i = 0; i < n; i++) {
            r[i + 1] = new byte[8];
            Buffer.BlockCopy(plaintext, i * 8, r[i + 1], 0, 8);
        }

        using (Aes aes = Aes.Create()) {
            aes.Key = kek;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            using (ICryptoTransform encryptor = aes.CreateEncryptor()) {
                byte[] block = new byte[16];
                byte[] enc = new byte[16];

                for (int j = 0; j <= 5; j++) {
                    for (int i = 1; i <= n; i++) {
                        for (int k = 0; k < 8; k++) block[k] = (byte)(a >> ((7 - k) * 8));
                        Buffer.BlockCopy(r[i], 0, block, 8, 8);
                        encryptor.TransformBlock(block, 0, 16, enc, 0);

                        ulong b_msb = 0;
                        for (int k = 0; k < 8; k++) b_msb = (b_msb << 8) | enc[k];
                        ulong t = (ulong)(n * j + i);
                        a = b_msb ^ t;

                        Buffer.BlockCopy(enc, 8, r[i], 0, 8);
                    }
                }
            }
        }

        byte[] result = new byte[(n + 1) * 8];
        for (int k = 0; k < 8; k++) result[k] = (byte)(a >> ((7 - k) * 8));
        for (int i = 1; i <= n; i++) {
            Buffer.BlockCopy(r[i], 0, result, i * 8, 8);
        }
        return result;
    }

    // -------------------------------------------------------------
    // RSA PKCS#1 v1.5 Encryption (for RSA 2048 ID cards)
    // -------------------------------------------------------------
    public static byte[] EncryptRsaPkcs1(X509Certificate2 cert, byte[] plaintext) {
        using (RSA rsa = cert.GetRSAPublicKey()) {
            if (rsa == null) throw new InvalidOperationException("Could not obtain RSA public key from certificate.");
            return rsa.Encrypt(plaintext, RSAEncryptionPadding.Pkcs1);
        }
    }

    // -------------------------------------------------------------
    // Windows CNG Native P/Invoke for AES-256-GCM & ECDH P-384
    // Built into every Windows 10, 11, and Windows Server (bcrypt.dll)
    // -------------------------------------------------------------
    [StructLayout(LayoutKind.Sequential)]
    private struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
        public int cbSize;
        public int dwInfoVersion;
        public IntPtr pbNonce;
        public int cbNonce;
        public IntPtr pbAuthData;
        public int cbAuthData;
        public IntPtr pbTag;
        public int cbTag;
        public IntPtr pbMacContext;
        public int cbMacContext;
        public int cbAAD;
        public long cbData;
        public int dwFlags;

        public static BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO Create() {
            var info = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
            info.cbSize = Marshal.SizeOf(typeof(BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO));
            info.dwInfoVersion = 1;
            return info;
        }
    }

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptOpenAlgorithmProvider(out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptSetProperty(IntPtr hObject, string pszProperty, string pszInput, int cbInput, uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptGenerateSymmetricKey(IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject, byte[] pbSecret, int cbSecret, uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptEncrypt(IntPtr hKey, byte[] pbInput, int cbInput, ref BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO pPaddingInfo, byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptGenerateKeyPair(IntPtr hAlgorithm, out IntPtr phKey, int dwLength, uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptFinalizeKeyPair(IntPtr hKey, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptImportKeyPair(IntPtr hAlgorithm, IntPtr hImportKey, string pszBlobType, out IntPtr phKey, byte[] pbInput, int cbInput, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptExportKey(IntPtr hKey, IntPtr hExportKey, string pszBlobType, byte[] pbOutput, int cbOutput, out int pcbResult, uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptSecretAgreement(IntPtr hPrivKey, IntPtr hPubKey, out IntPtr phAgreedSecret, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptDeriveKey(IntPtr hSharedSecret, string KDF, IntPtr pParameterList, byte[] pbDerivedKey, int cbDerivedKey, out int pcbResult, uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptDestroyKey(IntPtr hKey);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptDestroySecret(IntPtr hSecret);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

    public static byte[] EncryptAes256Gcm(byte[] key, byte[] iv, byte[] plaintext) {
        IntPtr hAlg = IntPtr.Zero;
        IntPtr hKey = IntPtr.Zero;
        GCHandle nonceHandle = default(GCHandle);
        GCHandle tagHandle = default(GCHandle);

        try {
            int status = BCryptOpenAlgorithmProvider(out hAlg, "AES", null, 0);
            if (status != 0) throw new CryptographicException("BCryptOpenAlgorithmProvider(AES) failed: 0x" + status.ToString("X8"));

            string chainingMode = "ChainingModeGCM";
            status = BCryptSetProperty(hAlg, "ChainingMode", chainingMode, (chainingMode.Length + 1) * 2, 0);
            if (status != 0) throw new CryptographicException("BCryptSetProperty(ChainingModeGCM) failed: 0x" + status.ToString("X8"));

            status = BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0);
            if (status != 0) throw new CryptographicException("BCryptGenerateSymmetricKey failed: 0x" + status.ToString("X8"));

            byte[] tag = new byte[16];
            tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);
            nonceHandle = GCHandle.Alloc(iv, GCHandleType.Pinned);

            var info = BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO.Create();
            info.pbNonce = nonceHandle.AddrOfPinnedObject();
            info.cbNonce = iv.Length;
            info.pbTag = tagHandle.AddrOfPinnedObject();
            info.cbTag = tag.Length;

            byte[] ciphertext = new byte[plaintext.Length];
            int cbResult = 0;
            status = BCryptEncrypt(hKey, plaintext, plaintext.Length, ref info, null, 0, ciphertext, ciphertext.Length, out cbResult, 0);
            if (status != 0) throw new CryptographicException("BCryptEncrypt(GCM) failed: 0x" + status.ToString("X8"));

            // XML-ENC 1.1 AES-GCM CipherValue layout: IV (12 bytes) || Ciphertext (N bytes) || Tag (16 bytes)
            byte[] output = new byte[iv.Length + ciphertext.Length + tag.Length];
            Buffer.BlockCopy(iv, 0, output, 0, iv.Length);
            Buffer.BlockCopy(ciphertext, 0, output, iv.Length, ciphertext.Length);
            Buffer.BlockCopy(tag, 0, output, iv.Length + ciphertext.Length, tag.Length);
            return output;
        }
        finally {
            if (nonceHandle.IsAllocated) nonceHandle.Free();
            if (tagHandle.IsAllocated) tagHandle.Free();
            if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
            if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
        }
    }

    public class EcdhAgreementResult {
        public byte[] SharedSecret;          // 48 bytes
        public byte[] EphemeralPublicKeyDer; // 97 bytes (0x04 || X || Y)
    }

    public static EcdhAgreementResult PerformEcdhAgreement(X509Certificate2 recipientCert) {
        byte[] rawPubKey = recipientCert.PublicKey.EncodedKeyValue.RawData;
        if (rawPubKey.Length != 97 || rawPubKey[0] != 0x04) {
            throw new NotSupportedException("Recipient certificate does not contain an uncompressed NIST P-384 public key");
        }

        byte[] x = new byte[48];
        byte[] y = new byte[48];
        Buffer.BlockCopy(rawPubKey, 1, x, 0, 48);
        Buffer.BlockCopy(rawPubKey, 49, y, 0, 48);

        // BCRYPT_ECCKEY_BLOB for ECDH P-384 public key
        // Magic = BCRYPT_ECDH_PUBLIC_P384_MAGIC = 0x334B4345 ("ECK3")
        byte[] blob = new byte[8 + 48 + 48];
        blob[0] = 0x45; blob[1] = 0x43; blob[2] = 0x4B; blob[3] = 0x33;
        blob[4] = 48; blob[5] = 0; blob[6] = 0; blob[7] = 0;
        Buffer.BlockCopy(x, 0, blob, 8, 48);
        Buffer.BlockCopy(y, 0, blob, 56, 48);

        IntPtr hAlg = IntPtr.Zero;
        IntPtr hEphPrivKey = IntPtr.Zero;
        IntPtr hRecipientPubKey = IntPtr.Zero;
        IntPtr hSecret = IntPtr.Zero;

        try {
            int status = BCryptOpenAlgorithmProvider(out hAlg, "ECDH_P384", null, 0);
            if (status != 0) throw new CryptographicException("BCryptOpenAlgorithmProvider(ECDH_P384) failed: 0x" + status.ToString("X8"));

            status = BCryptGenerateKeyPair(hAlg, out hEphPrivKey, 384, 0);
            if (status != 0) throw new CryptographicException("BCryptGenerateKeyPair failed: 0x" + status.ToString("X8"));

            status = BCryptFinalizeKeyPair(hEphPrivKey, 0);
            if (status != 0) throw new CryptographicException("BCryptFinalizeKeyPair failed: 0x" + status.ToString("X8"));

            int cbBlob = 0;
            status = BCryptExportKey(hEphPrivKey, IntPtr.Zero, "ECCPUBLICBLOB", null, 0, out cbBlob, 0);
            byte[] ephBlob = new byte[cbBlob];
            status = BCryptExportKey(hEphPrivKey, IntPtr.Zero, "ECCPUBLICBLOB", ephBlob, ephBlob.Length, out cbBlob, 0);

            byte[] ephPubKeyUncompressed = new byte[97];
            ephPubKeyUncompressed[0] = 0x04;
            Buffer.BlockCopy(ephBlob, 8, ephPubKeyUncompressed, 1, 48);
            Buffer.BlockCopy(ephBlob, 56, ephPubKeyUncompressed, 49, 48);

            status = BCryptImportKeyPair(hAlg, IntPtr.Zero, "ECCPUBLICBLOB", out hRecipientPubKey, blob, blob.Length, 0);
            if (status != 0) throw new CryptographicException("BCryptImportKeyPair failed: 0x" + status.ToString("X8"));

            status = BCryptSecretAgreement(hEphPrivKey, hRecipientPubKey, out hSecret, 0);
            if (status != 0) throw new CryptographicException("BCryptSecretAgreement failed: 0x" + status.ToString("X8"));

            int cbSecret = 0;
            status = BCryptDeriveKey(hSecret, "TRUNCATE", IntPtr.Zero, null, 0, out cbSecret, 0);
            if (cbSecret <= 0) cbSecret = 48;
            byte[] rawSecret = new byte[cbSecret];
            status = BCryptDeriveKey(hSecret, "TRUNCATE", IntPtr.Zero, rawSecret, rawSecret.Length, out cbSecret, 0);
            if (status != 0) throw new CryptographicException("BCryptDeriveKey(TRUNCATE) failed: 0x" + status.ToString("X8"));

            // Windows CNG BCRYPT_KDF_RAW_SECRET ("TRUNCATE") returns the raw ECDH shared secret in LITTLE-ENDIAN order.
            // PKCS#11, OpenSSL, NIST SP 800-56A and smart cards expect BIG-ENDIAN (network byte order).
            // Reverse the array to convert to big-endian:
            Array.Reverse(rawSecret);

            return new EcdhAgreementResult {
                SharedSecret = rawSecret,
                EphemeralPublicKeyDer = ephPubKeyUncompressed
            };
        }
        finally {
            if (hSecret != IntPtr.Zero) BCryptDestroySecret(hSecret);
            if (hRecipientPubKey != IntPtr.Zero) BCryptDestroyKey(hRecipientPubKey);
            if (hEphPrivKey != IntPtr.Zero) BCryptDestroyKey(hEphPrivKey);
            if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
        }
    }

    public static byte[] GenerateRandomBytes(int length) {
        byte[] bytes = new byte[length];
        using (var rng = RandomNumberGenerator.Create()) {
            rng.GetBytes(bytes);
        }
        return bytes;
    }
}
"@

if (-not ([System.Management.Automation.PSTypeName]'CdocCryptoEngine').Type) {
    Add-Type -TypeDefinition $script:CdocCryptoDefinition
}
