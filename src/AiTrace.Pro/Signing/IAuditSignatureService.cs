namespace AiTrace.Pro.Signing;

/// <summary>
/// Signs and verifies audit record hashes.
/// Pro feature: used to produce cryptographically verifiable evidence.
/// </summary>
public interface IAuditSignatureService
{
    /// <summary>
    /// Produces a Base64 signature of the provided hash (hex string).
    /// </summary>
    string Sign(string hashSha256Hex);

    /// <summary>
    /// Verifies a Base64 signature against the provided hash (hex string).
    /// </summary>
    bool Verify(string hashSha256Hex, string signatureBase64);
}
