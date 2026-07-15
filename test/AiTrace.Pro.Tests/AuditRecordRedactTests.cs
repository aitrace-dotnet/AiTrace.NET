namespace AiTrace.Pro.Tests;

/// <summary>
/// Tests for AuditRecord.Redact() via AuditRecord.Create() with basicRedaction = true.
/// </summary>
public class AuditRecordRedactTests
{
    private static AuditRecord CreateWithRedaction(string prompt, string output)
    {
        var decision = new AiDecision
        {
            Prompt = prompt,
            Output = output,
            Model = "test",
            UserId = "u1"
        };
        return AuditRecord.Create(decision, DateTimeOffset.UtcNow, string.Empty, storeContent: true, basicRedaction: true);
    }

    [Fact]
    public void Redact_BearerToken_IsReplaced()
    {
        var record = CreateWithRedaction("Authorization: Bearer abc123.def456.ghi789", "ok");
        Assert.DoesNotContain("abc123", record.Prompt ?? "");
        Assert.Contains("REDACTED", record.Prompt ?? "");
    }

    [Fact]
    public void Redact_ApiKey_IsReplaced()
    {
        var record = CreateWithRedaction("api_key: sk-abcdefghijklmnopqrstuvwxyz1234", "ok");
        Assert.DoesNotContain("sk-abcdefghijklmnopqrstuvwxyz1234", record.Prompt ?? "");
        Assert.Contains("REDACTED", record.Prompt ?? "");
    }

    [Fact]
    public void Redact_SecretField_IsReplaced()
    {
        var record = CreateWithRedaction("secret=mysupersecretvalue123456", "ok");
        Assert.DoesNotContain("mysupersecretvalue123456", record.Prompt ?? "");
        Assert.Contains("REDACTED", record.Prompt ?? "");
    }

    [Fact]
    public void Redact_NormalText_IsNotAffected()
    {
        const string text = "Hello world, how are you?";
        var record = CreateWithRedaction(text, text);
        Assert.Equal(text, record.Prompt);
        Assert.Equal(text, record.Output);
    }

    [Fact]
    public void Redact_Output_IsAlsoRedacted()
    {
        var record = CreateWithRedaction("normal", "Bearer eyJhbGciOiJIUzI1NiJ9.abc");
        Assert.DoesNotContain("eyJhbGciOiJIUzI1NiJ9", record.Output ?? "");
        Assert.Contains("REDACTED", record.Output ?? "");
    }

    [Fact]
    public void NoRedaction_ContentIsStoredAsIs()
    {
        var decision = new AiDecision
        {
            Prompt = "Bearer secret123456789012",
            Output = "api_key: supersecret12345678",
            Model = "test",
            UserId = "u1"
        };
        var record = AuditRecord.Create(decision, DateTimeOffset.UtcNow, string.Empty, storeContent: true, basicRedaction: false);
        Assert.Equal(decision.Prompt, record.Prompt);
        Assert.Equal(decision.Output, record.Output);
    }
}
