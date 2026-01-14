namespace AiTrace.Pro.Verification;

/// <summary>
/// Defines strictness rules for audit verification.
/// Used to enforce compliance, CI, or regulatory requirements.
/// </summary>
public sealed class VerificationPolicy
{
    /// <summary>
    /// Require cryptographic signatures on all records.
    /// </summary>
    public bool RequireSignatures { get; init; }

    /// <summary>
    /// Require PrevHashSha256 chain integrity.
    /// </summary>
    public bool RequireChainIntegrity { get; init; } = true;

    /// <summary>
    /// Fail verification if any audit file is missing or unreadable.
    /// </summary>
    public bool FailOnMissingFiles { get; init; }

    // ---------- Presets ----------

    /// <summary>
    /// Strict policy suitable for CI/CD and regulators.
    /// </summary>
    public static VerificationPolicy Strict()
        => new()
        {
            RequireSignatures = true,
            RequireChainIntegrity = true,
            FailOnMissingFiles = true
        };

    /// <summary>
    /// Relaxed policy for local development or debugging.
    /// </summary>
    public static VerificationPolicy Relaxed()
        => new()
        {
            RequireSignatures = false,
            RequireChainIntegrity = true,
            FailOnMissingFiles = false
        };
}
