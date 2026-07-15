namespace AiTrace.Pro.Tests;

public class AuditHasherTests
{
    [Fact]
    public void Sha256Hex_IsDeterministic()
    {
        var h1 = AuditHasher.Sha256Hex("hello world");
        var h2 = AuditHasher.Sha256Hex("hello world");
        Assert.Equal(h1, h2);
    }

    [Fact]
    public void Sha256Hex_DifferentInputs_ProduceDifferentHashes()
    {
        var h1 = AuditHasher.Sha256Hex("foo");
        var h2 = AuditHasher.Sha256Hex("bar");
        Assert.NotEqual(h1, h2);
    }

    [Fact]
    public void Sha256Hex_ProducesLowercaseHex()
    {
        var h = AuditHasher.Sha256Hex("abc");
        // Result must be 64 hex chars, all lowercase.
        Assert.Equal(64, h.Length);
        Assert.Equal(h, h.ToLowerInvariant());
        Assert.Matches("^[0-9a-f]{64}$", h);
    }

    [Fact]
    public void BuildHashMaterial_IsDeterministic()
    {
        var record = MakeRecord();
        var m1 = AuditHasher.BuildHashMaterial(record);
        var m2 = AuditHasher.BuildHashMaterial(record);
        Assert.Equal(m1, m2);
    }

    [Fact]
    public void ComputeRecordHash_IsDeterministic()
    {
        var record = MakeRecord();
        var h1 = AuditHasher.ComputeRecordHash(record);
        var h2 = AuditHasher.ComputeRecordHash(record);
        Assert.Equal(h1, h2);
    }

    [Fact]
    public void ComputeRecordHash_ChangesWhenRecordChanges()
    {
        var record = MakeRecord();
        var h1 = AuditHasher.ComputeRecordHash(record);

        var record2 = record with { UserId = "other-user" };
        var h2 = AuditHasher.ComputeRecordHash(record2);

        Assert.NotEqual(h1, h2);
    }

    [Fact]
    public void ComputeRecordHash_IncludesPrevHash()
    {
        var record = MakeRecord();
        record.PrevHashSha256 = null;
        var h1 = AuditHasher.ComputeRecordHash(record);

        record.PrevHashSha256 = "abc123";
        var h2 = AuditHasher.ComputeRecordHash(record);

        Assert.NotEqual(h1, h2);
    }

    private static AuditRecord MakeRecord() => new AuditRecord
    {
        Id = "test-id",
        TimestampUtc = new DateTimeOffset(2024, 1, 1, 0, 0, 0, TimeSpan.Zero),
        Model = "gpt-4",
        UserId = "user-1",
        ContentStored = true,
        Prompt = "Hello",
        Output = "World",
        MetadataJson = "{}"
    };
}
