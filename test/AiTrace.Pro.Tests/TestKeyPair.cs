using System.Security.Cryptography;

namespace AiTrace.Pro.Tests;

/// <summary>
/// Generates a fresh RSA key pair (in-memory) for use in tests.
/// </summary>
internal static class TestKeyPair
{
    internal static (string PrivatePem, string PublicPem) Generate()
    {
        using var rsa = RSA.Create(2048);
        var privatePem = rsa.ExportRSAPrivateKeyPem();
        var publicPem = rsa.ExportSubjectPublicKeyInfoPem();
        return (privatePem, publicPem);
    }
}
