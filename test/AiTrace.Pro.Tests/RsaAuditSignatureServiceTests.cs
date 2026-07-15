using AiTrace.Pro.Signing;

namespace AiTrace.Pro.Tests;

public class RsaAuditSignatureServiceTests
{
    private static readonly (string PrivatePem, string PublicPem) Keys = TestKeyPair.Generate();

    [Fact]
    public void Sign_And_Verify_RoundTrip()
    {
        var signer = new RsaAuditSignatureService(Keys.PrivatePem);
        var verifier = new RsaAuditSignatureService(Keys.PublicPem);

        var hash = AuditHasher.Sha256Hex("some audit content");
        var sig = signer.Sign(hash);

        Assert.True(verifier.Verify(hash, sig));
    }

    [Fact]
    public void Verify_ReturnsFalse_WhenHashMismatch()
    {
        var signer = new RsaAuditSignatureService(Keys.PrivatePem);
        var verifier = new RsaAuditSignatureService(Keys.PublicPem);

        var hash = AuditHasher.Sha256Hex("original");
        var sig = signer.Sign(hash);

        var otherHash = AuditHasher.Sha256Hex("tampered");
        Assert.False(verifier.Verify(otherHash, sig));
    }

    [Fact]
    public void Verify_ReturnsFalse_WhenSignatureCorrupted()
    {
        var signer = new RsaAuditSignatureService(Keys.PrivatePem);
        var verifier = new RsaAuditSignatureService(Keys.PublicPem);

        var hash = AuditHasher.Sha256Hex("content");
        _ = signer.Sign(hash);

        // Completely invalid base64 should not throw
        Assert.False(verifier.Verify(hash, "this-is-not-valid-base64!!!"));
    }

    [Fact]
    public void Verify_ReturnsFalse_WhenSignatureIsBase64ButWrongData()
    {
        var signer = new RsaAuditSignatureService(Keys.PrivatePem);
        var verifier = new RsaAuditSignatureService(Keys.PublicPem);

        var hash = AuditHasher.Sha256Hex("content");
        var sig = signer.Sign(hash);

        // Corrupt by reversing the base64 string
        var corrupted = Convert.ToBase64String(new byte[256]); // 256 zeroed bytes
        Assert.False(verifier.Verify(hash, corrupted));
    }

    [Fact]
    public void Sign_ThrowsArgumentException_WhenHashIsEmpty()
    {
        var signer = new RsaAuditSignatureService(Keys.PrivatePem);
        Assert.Throws<ArgumentException>(() => signer.Sign(""));
    }

    [Fact]
    public void Verify_ReturnsFalse_WhenHashIsEmpty()
    {
        var verifier = new RsaAuditSignatureService(Keys.PublicPem);
        Assert.False(verifier.Verify("", "someSig"));
    }
}
