namespace AiTrace.Pro.Verification;

public enum SignatureStatus
{
    NotChecked = 0,
    Valid = 1,
    Invalid = 2,
    Missing = 3
}

/// <summary>
/// High-level compliance-oriented summary (for reports/exports).
/// </summary>
public sealed class ComplianceVerificationSummary
{
    public VerificationStatus Status { get; init; } = VerificationStatus.Ok;

    public bool IsValid { get; init; }

    public bool IntegrityVerified { get; init; }
    public bool ChainVerified { get; init; }

    public bool AnySignaturePresent { get; init; }
    public bool SignatureRequired { get; init; }
    public SignatureStatus SignatureStatus { get; init; } = SignatureStatus.NotChecked;

    public int FilesVerified { get; init; }
    public int RecordsVerified { get; init; }

    public DateTimeOffset? FirstTimestampUtc { get; init; }
    public DateTimeOffset? LastTimestampUtc { get; init; }

    public int? FailedIndex { get; init; }
    public string? FailedFileName { get; init; }
    public string? Reason { get; init; }
}