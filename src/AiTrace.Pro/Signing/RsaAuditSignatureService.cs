using System.Security.Cryptography;
using System.Text;

namespace AiTrace.Pro.Signing;

/// <summary>
/// RSA-based audit signature service.
/// Signs audit record hashes using a private key
/// and verifies signatures using the corresponding public key.
/// </summary>
public sealed class RsaAuditSignatureService : IAuditSignatureService
{
    private readonly RSA _rsa;

    /// <summary>
    /// Creates the service using a PEM-encoded RSA key (private for signing, public for verifying).
    /// </summary>
    public RsaAuditSignatureService(string publicOrPrivateKeyPem)
    {
        if (string.IsNullOrWhiteSpace(publicOrPrivateKeyPem))
            throw new ArgumentException("PEM key is required.", nameof(publicOrPrivateKeyPem));

        _rsa = RSA.Create();
        _rsa.ImportFromPem(publicOrPrivateKeyPem);
    }

    /// <summary>
    /// Signs a SHA-256 hash (hex string) and returns a Base64 signature.
    /// </summary>
    public string Sign(string hashSha256Hex)
    {
        if (string.IsNullOrWhiteSpace(hashSha256Hex))
            throw new ArgumentException("Hash is required.", nameof(hashSha256Hex));

        // You sign the actual 32-byte hash value (decoded from hex)
        var hashBytes = HexToBytes(hashSha256Hex);

        var signature = _rsa.SignHash(
            hashBytes,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );

        return Convert.ToBase64String(signature);
    }

    /// <summary>
    /// Verifies a Base64 signature against a SHA-256 hash (hex string).
    /// Never throws: any malformed signature/key is treated as invalid.
    /// </summary>
    public bool Verify(string hashSha256Hex, string signatureBase64)
    {
        if (string.IsNullOrWhiteSpace(hashSha256Hex)) return false;
        if (string.IsNullOrWhiteSpace(signatureBase64)) return false;

        try
        {
            var hashBytes = HexToBytes(hashSha256Hex);

            // IMPORTANT: corrupted / non-base64 signature should NOT throw
            byte[] signatureBytes;
            try
            {
                signatureBytes = Convert.FromBase64String(signatureBase64);
            }
            catch (FormatException)
            {
                return false; // treat as invalid signature
            }

            return _rsa.VerifyHash(
                hashBytes,
                signatureBytes,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1
            );
        }
        catch
        {
            // any crypto/import/hex edge-case => invalid
            return false;
        }
    }

    private static byte[] HexToBytes(string hex)
    {
        if (string.IsNullOrWhiteSpace(hex))
            throw new ArgumentException("Invalid hex string.", nameof(hex));

        hex = hex.Trim();

        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            hex = hex[2..];

        if (hex.Length % 2 != 0)
            throw new ArgumentException("Invalid hex string length.", nameof(hex));

        var bytes = new byte[hex.Length / 2];

        for (int i = 0; i < bytes.Length; i++)
        {
            var hi = FromHexNibble(hex[2 * i]);
            var lo = FromHexNibble(hex[2 * i + 1]);
            bytes[i] = (byte)((hi << 4) | lo);
        }

        return bytes;

        static int FromHexNibble(char c)
        {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            throw new ArgumentException("Invalid hex character.");
        }
    }
}