using AiTrace.Pro.Verification;

namespace AiTrace.Pro.Tests;

public class VerificationScopeTests
{
    private static AuditRecord MakeRecord(string userId = "u1", string model = "m1", DateTimeOffset? ts = null)
    {
        var r = new AuditRecord
        {
            Id = Guid.NewGuid().ToString("n"),
            TimestampUtc = ts ?? DateTimeOffset.UtcNow,
            UserId = userId,
            Model = model,
            ContentStored = false,
            MetadataJson = "{}"
        };
        r.HashSha256 = AuditHasher.ComputeRecordHash(r);
        return r;
    }

    [Fact]
    public void All_IncludesEverything()
    {
        var scope = VerificationScope.All();
        var r = MakeRecord();
        Assert.True(scope.Includes(r));
    }

    [Fact]
    public void Between_IncludesRecordInRange()
    {
        var now = DateTimeOffset.UtcNow;
        var scope = VerificationScope.Between(now.AddHours(-1), now.AddHours(1));
        var r = MakeRecord(ts: now);
        Assert.True(scope.Includes(r));
    }

    [Fact]
    public void Between_ExcludesRecordBeforeRange()
    {
        var now = DateTimeOffset.UtcNow;
        var scope = VerificationScope.Between(now, now.AddHours(1));
        var r = MakeRecord(ts: now.AddHours(-1));
        Assert.False(scope.Includes(r));
    }

    [Fact]
    public void Between_ExcludesRecordAfterRange()
    {
        var now = DateTimeOffset.UtcNow;
        var scope = VerificationScope.Between(now.AddHours(-1), now);
        var r = MakeRecord(ts: now.AddHours(1));
        Assert.False(scope.Includes(r));
    }

    [Fact]
    public void UserId_Filter_ExcludesOtherUsers()
    {
        var scope = new VerificationScope { UserId = "alice" };
        var alice = MakeRecord(userId: "alice");
        var bob = MakeRecord(userId: "bob");

        Assert.True(scope.Includes(alice));
        Assert.False(scope.Includes(bob));
    }

    [Fact]
    public void Model_Filter_ExcludesOtherModels()
    {
        var scope = new VerificationScope { Model = "gpt-4" };
        var gpt4 = MakeRecord(model: "gpt-4");
        var claude = MakeRecord(model: "claude-3");

        Assert.True(scope.Includes(gpt4));
        Assert.False(scope.Includes(claude));
    }

    [Fact]
    public void CombinedFilters_AllMustMatch()
    {
        var now = DateTimeOffset.UtcNow;
        var scope = new VerificationScope
        {
            FromUtc = now.AddHours(-1),
            ToUtc = now.AddHours(1),
            UserId = "alice",
            Model = "gpt-4"
        };

        var match = MakeRecord(userId: "alice", model: "gpt-4", ts: now);
        Assert.True(scope.Includes(match));

        var wrongUser = MakeRecord(userId: "bob", model: "gpt-4", ts: now);
        Assert.False(scope.Includes(wrongUser));

        var wrongModel = MakeRecord(userId: "alice", model: "claude", ts: now);
        Assert.False(scope.Includes(wrongModel));
    }

    [Fact]
    public void Includes_NullRecord_ReturnsFalse()
    {
        var scope = VerificationScope.All();
        Assert.False(scope.Includes(null!));
    }
}
