namespace AiTrace;

public static class AiTrace
{
    // Lock protecting concurrent Configure() calls.
    private static readonly object _configLock = new();

    private static AiTraceOptions _options = new();
    private static bool _configured;

    public static void Configure(Action<AiTraceOptions> configure)
    {
        if (configure is null) throw new ArgumentNullException(nameof(configure));

        lock (_configLock)
        {
            configure(_options);
            _configured = true;
        }
    }

    public static async Task LogDecisionAsync(AiDecision decision, CancellationToken ct = default)
    {
        if (decision is null) throw new ArgumentNullException(nameof(decision));

        // Snapshot options to avoid races with concurrent Configure() calls.
        AiTraceOptions opts;
        lock (_configLock)
        {
            if (!_configured) _configured = true;
            opts = _options;
        }

        var timestamp = decision.TimestampUtc ?? DateTimeOffset.UtcNow;

        // The store is responsible for computing the final hash (chain-aware).
        // Passing an empty placeholder here; WriteAsync overwrites it with the
        // correct chain hash via AuditHasher.ComputeRecordHash().
        var record = AuditRecord.Create(decision, timestamp, string.Empty, opts.StoreContent, opts.BasicRedaction);
        await opts.Store.WriteAsync(record, ct).ConfigureAwait(false);
    }
}
