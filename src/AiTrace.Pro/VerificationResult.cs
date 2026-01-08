namespace AiTrace.Pro.Verification;

public sealed class VerificationResult
{
    /// <summary>
    /// True if the audit trail is fully valid.
    /// </summary>
    public bool IsValid { get; init; }

    /// <summary>
    /// High-level verification outcome.
    /// </summary>
    public VerificationStatus Status { get; init; } = VerificationStatus.Ok;

    /// <summary>
    /// Index of the file that failed verification (0-based).
    /// </summary>
    public int? FailedIndex { get; init; }

    /// <summary>
    /// File name related to the failure (if applicable).
    /// </summary>
    public string? FileName { get; init; }

    /// <summary>
    /// Human-readable explanation of the verification result.
    /// </summary>
    public string? Reason { get; init; }

    /// <summary>
    /// Indicates whether signature verification was attempted.
    /// </summary>
    public bool SignatureChecked { get; init; }

    /// <summary>
    /// Indicates whether the signature was valid (if checked).
    /// </summary>
    public bool SignatureValid { get; init; }

    // ---- Factory helpers ----

    public static VerificationResult Ok()
        => new()
        {
            IsValid = true,
            Status = VerificationStatus.Ok,
            SignatureChecked = true,
            SignatureValid = true
        };

    public static VerificationResult Fail(
        VerificationStatus status,
        int index,
        string reason,
        string? fileName = null,
        bool signatureChecked = false,
        bool signatureValid = false)
        => new()
        {
            IsValid = false,
            Status = status,
            FailedIndex = index,
            FileName = fileName,
            Reason = reason,
            SignatureChecked = signatureChecked,
            SignatureValid = signatureValid
        };

    // ---- Backward compatibility (optional but recommended) ----
    // Allows existing code to keep calling Fail(int, string)

    public static VerificationResult Fail(int index, string reason)
        => Fail(
            VerificationStatus.ParseError,
            index,
            reason
        );
}
