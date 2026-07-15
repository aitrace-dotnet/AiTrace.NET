using System.Text.Json;
using AiTrace.Pro.Licensing;
using AiTrace.Pro.Signing;
using AiTrace.Pro.Verification;

namespace AiTrace.Pro.Tests;

public class ChainVerifierTests : IDisposable
{
    private readonly string _dir;
    private static readonly (string PrivatePem, string PublicPem) Keys = TestKeyPair.Generate();

    public ChainVerifierTests()
    {
        // Each test gets its own isolated directory.
        _dir = Path.Combine(Path.GetTempPath(), "AiTraceProTests", Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(_dir);

        // Disable license for tests
        LicenseGuard.Mode = LicenseMode.Disabled;
    }

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { }
    }

    // -------------------------------------------------------
    // Helpers
    // -------------------------------------------------------

    private static AuditRecord MakeRecord(string id, DateTimeOffset ts, string? prevHash = null)
    {
        var r = new AuditRecord
        {
            Id = id,
            TimestampUtc = ts,
            Model = "test-model",
            UserId = "user-1",
            ContentStored = true,
            Prompt = "P",
            Output = "O",
            MetadataJson = "{}",
            PrevHashSha256 = prevHash
        };
        r.HashSha256 = AuditHasher.ComputeRecordHash(r);
        return r;
    }

    private void WriteRecord(AuditRecord r)
    {
        var fileName = $"{r.TimestampUtc:yyyyMMdd_HHmmssfff}_{r.Id}.json";
        var json = JsonSerializer.Serialize(r, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(Path.Combine(_dir, fileName), json);
    }

    private ChainVerifier MakeRelaxedVerifier()
        => new ChainVerifier(new SignatureOptions(), VerificationPolicy.Relaxed());

    private ChainVerifier MakeStrictVerifier()
    {
        var sigOpts = new SignatureOptions
        {
            SignatureService = new RsaAuditSignatureService(Keys.PublicPem)
        };
        return new ChainVerifier(sigOpts, VerificationPolicy.Strict());
    }

    // -------------------------------------------------------
    // Basic happy-path tests
    // -------------------------------------------------------

    [Fact]
    public void Verify_EmptyDirectory_ReturnsNoFiles()
    {
        var verifier = MakeRelaxedVerifier();
        var result = verifier.Verify(_dir);
        Assert.False(result.IsValid);
        Assert.Equal(VerificationStatus.NoFiles, result.Status);
    }

    [Fact]
    public void Verify_SingleValidRecord_ReturnsOk()
    {
        var r = MakeRecord("id1", DateTimeOffset.UtcNow);
        WriteRecord(r);

        var result = MakeRelaxedVerifier().Verify(_dir);
        Assert.True(result.IsValid);
        Assert.Equal(VerificationStatus.Ok, result.Status);
    }

    [Fact]
    public void Verify_ChainedRecords_ReturnsOk()
    {
        var ts = DateTimeOffset.UtcNow;
        var r1 = MakeRecord("id1", ts);
        WriteRecord(r1);

        var r2 = MakeRecord("id2", ts.AddSeconds(1), r1.HashSha256);
        WriteRecord(r2);

        var result = MakeRelaxedVerifier().Verify(_dir);
        Assert.True(result.IsValid);
    }

    // -------------------------------------------------------
    // Hash mismatch
    // -------------------------------------------------------

    [Fact]
    public void Verify_TamperedRecord_ReturnsHashMismatch()
    {
        var r = MakeRecord("id1", DateTimeOffset.UtcNow);
        // Tamper: wrong hash stored
        r.HashSha256 = "deadbeef" + r.HashSha256[8..];
        WriteRecord(r);

        var result = MakeRelaxedVerifier().Verify(_dir);
        Assert.False(result.IsValid);
        Assert.Equal(VerificationStatus.HashMismatch, result.Status);
    }

    // -------------------------------------------------------
    // Chain broken
    // -------------------------------------------------------

    [Fact]
    public void Verify_BrokenChain_ReturnsChainBroken()
    {
        var ts = DateTimeOffset.UtcNow;
        var r1 = MakeRecord("id1", ts);
        WriteRecord(r1);

        // r2 claims a wrong prev hash
        var r2 = MakeRecord("id2", ts.AddSeconds(1), "wrongprevhash");
        WriteRecord(r2);

        var result = MakeRelaxedVerifier().Verify(_dir);
        Assert.False(result.IsValid);
        Assert.Equal(VerificationStatus.ChainBroken, result.Status);
    }

    // -------------------------------------------------------
    // Strict policy — signature required
    // -------------------------------------------------------

    [Fact]
    public void Verify_StrictPolicy_RecordWithoutSignature_Fails()
    {
        var r = MakeRecord("id1", DateTimeOffset.UtcNow);
        WriteRecord(r);

        var result = MakeStrictVerifier().Verify(_dir);
        Assert.False(result.IsValid);
        Assert.Equal(VerificationStatus.SignatureRequiredButMissing, result.Status);
    }

    [Fact]
    public void Verify_StrictPolicy_SignedRecord_Succeeds()
    {
        var signer = new RsaAuditSignatureService(Keys.PrivatePem);
        var r = MakeRecord("id1", DateTimeOffset.UtcNow);
        var signed = r with { Signature = signer.Sign(r.HashSha256), SignatureAlgorithm = "RSA-SHA256" };
        WriteRecord(signed);

        var result = MakeStrictVerifier().Verify(_dir);
        Assert.True(result.IsValid);
    }

    // -------------------------------------------------------
    // Relaxed policy
    // -------------------------------------------------------

    [Fact]
    public void Verify_RelaxedPolicy_RecordWithoutSignature_Succeeds()
    {
        var r = MakeRecord("id1", DateTimeOffset.UtcNow);
        WriteRecord(r);

        var result = MakeRelaxedVerifier().Verify(_dir);
        Assert.True(result.IsValid);
    }

    // -------------------------------------------------------
    // VerifySummary + scope filtering
    // -------------------------------------------------------

    [Fact]
    public void VerifySummary_ScopeByUserId_FiltersCorrectly()
    {
        var ts = DateTimeOffset.UtcNow;
        var r1 = MakeRecord("id1", ts) with { UserId = "alice" };
        r1.HashSha256 = AuditHasher.ComputeRecordHash(r1);
        WriteRecord(r1);

        var r2 = MakeRecord("id2", ts.AddSeconds(1)) with { UserId = "bob" };
        r2.HashSha256 = AuditHasher.ComputeRecordHash(r2);
        WriteRecord(r2);

        var verifier = MakeRelaxedVerifier();

        var scope = new VerificationScope { UserId = "alice" };
        var summary = verifier.VerifySummary(_dir, signatureRequired: false, scope: scope);

        Assert.Equal(1, summary.FilesVerified);
    }

    [Fact]
    public void VerifySummary_ScopeByModel_FiltersCorrectly()
    {
        var ts = DateTimeOffset.UtcNow;

        var r1 = MakeRecord("id1", ts) with { Model = "gpt-4" };
        r1.HashSha256 = AuditHasher.ComputeRecordHash(r1);
        WriteRecord(r1);

        var r2 = MakeRecord("id2", ts.AddSeconds(1)) with { Model = "claude-3" };
        r2.HashSha256 = AuditHasher.ComputeRecordHash(r2);
        WriteRecord(r2);

        var verifier = MakeRelaxedVerifier();
        var scope = new VerificationScope { Model = "gpt-4" };
        var summary = verifier.VerifySummary(_dir, signatureRequired: false, scope: scope);

        Assert.Equal(1, summary.FilesVerified);
    }
}
