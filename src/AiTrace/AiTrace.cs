using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AiTrace;

public static class AiTrace
{
    private static AiTraceOptions _options = new();
    private static bool _configured;

    public static void Configure(Action<AiTraceOptions> configure)
    {
        if (configure is null) throw new ArgumentNullException(nameof(configure));
        configure(_options);
        _configured = true;
    }

    public static async Task LogDecisionAsync(AiDecision decision, CancellationToken ct = default)
    {
        if (decision is null) throw new ArgumentNullException(nameof(decision));
        if (!_configured)
        {
            // Default configuration is fine; this just documents intent.
            _configured = true;
        }

        var timestamp = decision.TimestampUtc ?? DateTimeOffset.UtcNow;

        // Minimal canonical payload for hashing
        var canonical = new
        {
            timestamp = timestamp.ToString("O"),
            decision.Prompt,
            decision.Output,
            decision.Model,
            decision.UserId,
            metadata = decision.Metadata
        };

        var canonicalJson = JsonSerializer.Serialize(canonical);
        var hash = ComputeSha256Hex(canonicalJson);

        var record = AuditRecord.Create(decision, timestamp, hash, _options.StoreContent, _options.BasicRedaction);
        await _options.Store.WriteAsync(record, ct).ConfigureAwait(false);
    }

    private static string ComputeSha256Hex(string input)
    {
        var bytes = Encoding.UTF8.GetBytes(input);
        var hash = SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
