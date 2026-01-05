using System.Text.Json;
using System.Text.RegularExpressions;

namespace AiTrace;

public sealed record AuditRecord
{
    public required string Id { get; init; }                 // Unique id for this record
    public required DateTimeOffset TimestampUtc { get; init; }
    public required string HashSha256 { get; init; }          // Integrity proof

    public string? Model { get; init; }
    public string? UserId { get; init; }

    public bool ContentStored { get; init; }

    // Content (optional depending on settings)
    public string? Prompt { get; init; }
    public string? Output { get; init; }

    // Minimal metadata (serialized as JSON string for easy storage)
    public string MetadataJson { get; init; } = "{}";

    public static AuditRecord Create(
        AiDecision decision,
        DateTimeOffset timestampUtc,
        string hashSha256,
        bool storeContent,
        bool basicRedaction)
    {
        if (decision is null) throw new ArgumentNullException(nameof(decision));

        var prompt = storeContent ? decision.Prompt : null;
        var output = storeContent ? decision.Output : null;

        if (basicRedaction && storeContent)
        {
            prompt = Redact(prompt);
            output = Redact(output);
        }

        var metadataJson = JsonSerializer.Serialize(decision.Metadata ?? new Dictionary<string, object?>());

        return new AuditRecord
        {
            Id = Guid.NewGuid().ToString("n"),
            TimestampUtc = timestampUtc,
            HashSha256 = hashSha256,
            Model = decision.Model,
            UserId = decision.UserId,
            ContentStored = storeContent,
            Prompt = prompt,
            Output = output,
            MetadataJson = metadataJson
        };
    }

    private static string? Redact(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return text;

        // Very basic redaction: remove common bearer tokens and long keys
        // This is intentionally conservative and simple for v1.
        text = Regex.Replace(text, @"(?i)bearer\s+[a-z0-9\-_\.=]+", "Bearer [REDACTED]");
        text = Regex.Replace(text, @"(?i)(api[_-]?key|secret|token)\s*[:=]\s*[a-z0-9\-_\.=]{12,}", "$1=[REDACTED]");
        return text;
    }
}
