namespace AiTrace.Pro.Verification;

/// <summary>
/// Defines strictness rules for audit verification.
/// Used to enforce compliance, CI, or regulatory requirements.
/// </summary>
public sealed class VerificationPolicy
{
    /// <summary>
    /// Require cryptographic signatures on all records being verified.
    /// </summary>
    public bool RequireSignatures { get; init; }

    /// <summary>
    /// Require PrevHashSha256 chain integrity on all records being verified.
    /// </summary>
    public bool RequireChainIntegrity { get; init; } = true;

    /// <summary>
    /// If true, allows verification of a scope (time window) that starts mid-chain.
    /// The first record inside the scope will not be required to match a previous hash outside the scope.
    /// Subsequent records inside the scope must still chain correctly.
    /// </summary>
    public bool AllowStartMidChain { get; init; } = true;

    /// <summary>
    /// Fail verification if any audit file is missing or unreadable.
    /// (Reserved for future: when a manifest/index exists.)
    /// </summary>
    public bool FailOnMissingFiles { get; init; }

    // ---------- Presets ----------

    /// <summary>
    /// Strict policy suitable for regulators.
    /// Often used with a time scope; allowStartMidChain should stay true.
    /// </summary>
    public static VerificationPolicy Strict()
        => new()
        {
            RequireSignatures = true,
            RequireChainIntegrity = true,
            AllowStartMidChain = true,
            FailOnMissingFiles = true
        };

    /// <summary>
    /// Strict policy for verifying a whole directory from the beginning of the chain.
    /// </summary>
    public static VerificationPolicy FullChainStrict()
        => new()
        {
            RequireSignatures = true,
            RequireChainIntegrity = true,
            AllowStartMidChain = false,
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
            AllowStartMidChain = true,
            FailOnMissingFiles = false
        };
}