namespace AiTrace.Pro.Verification;

/// <summary>
/// Defines which records are included in reporting/export scope (e.g., time range, user, model).
/// NOTE: This does NOT change integrity verification rules; it only filters what is counted/summarized.
/// </summary>
public sealed class VerificationScope
{
    public DateTimeOffset? FromUtc { get; init; }
    public DateTimeOffset? ToUtc { get; init; }

    /// <summary>
    /// Optional filter: only include records for this UserId.
    /// </summary>
    public string? UserId { get; init; }

    /// <summary>
    /// Optional filter: only include records for this Model.
    /// </summary>
    public string? Model { get; init; }

    public static VerificationScope All()
        => new();

    public static VerificationScope Between(DateTimeOffset fromUtc, DateTimeOffset toUtc)
        => new() { FromUtc = fromUtc, ToUtc = toUtc };

    public bool Includes(DateTimeOffset timestampUtc)
    {
        if (FromUtc.HasValue && timestampUtc < FromUtc.Value) return false;
        if (ToUtc.HasValue && timestampUtc > ToUtc.Value) return false;
        return true;
    }

    /// <summary>
    /// Convenience: checks timestamp + optional UserId/Model filters.
    /// </summary>
    public bool Includes(AuditRecord record)
    {
        if (record is null) return false;

        if (!Includes(record.TimestampUtc)) return false;

        if (!string.IsNullOrWhiteSpace(UserId) &&
            !string.Equals(record.UserId, UserId, StringComparison.Ordinal))
            return false;

        if (!string.IsNullOrWhiteSpace(Model) &&
            !string.Equals(record.Model, Model, StringComparison.Ordinal))
            return false;

        return true;
    }
}