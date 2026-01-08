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
    /// Creates the service using a PEM-encoded RSA private key.
    /// </summary>
    public RsaAuditSignatureService(string privateKeyPem)
    {
        if (string.IsNullOrWhiteSpace(privateKeyPem))
            throw new ArgumentException("Private key is required.", nameof(privateKeyPem));

        _rsa = RSA.Create();
        _rsa.ImportFromPem(privateKeyPem);
    }

    /// <summary>
    /// Signs a SHA-256 hash (hex string) and returns a Base64 signature.
    /// </summary>
    public string Sign(string hashSha256Hex)
    {
        if (string.IsNullOrWhiteSpace(hashSha256Hex))
            throw new ArgumentException("Hash is required.", nameof(hashSha256Hex));

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
    /// </summary>
    public bool Verify(string hashSha256Hex, string signatureBase64)
    {
        if (string.IsNullOrWhiteSpace(hashSha256Hex)) return false;
        if (string.IsNullOrWhiteSpace(signatureBase64)) return false;

        var hashBytes = HexToBytes(hashSha256Hex);
        var signatureBytes = Convert.FromBase64String(signatureBase64);

        return _rsa.VerifyHash(
            hashBytes,
            signatureBytes,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1
        );
    }

    private static byte[] HexToBytes(string hex)
    {
        if (hex.Length % 2 != 0)
            throw new ArgumentException("Invalid hex string length.", nameof(hex));

        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
        {
            bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
        }
        return bytes;
    }
}
