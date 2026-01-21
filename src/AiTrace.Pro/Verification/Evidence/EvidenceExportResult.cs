namespace AiTrace.Pro.Verification;

public sealed class EvidenceExportResult
{
    public bool Exported { get; init; }
    public string? OutputDirectory { get; init; }
    public string? AuditDirectory { get; init; }

    public string? TextReportPath { get; init; }
    public string? JsonReportPath { get; init; }
    public string? ReadmePath { get; init; }
    public string? ManifestPath { get; init; }

    public ComplianceVerificationSummary Summary { get; init; } = default!;

    public static EvidenceExportResult Fail(ComplianceVerificationSummary summary)
        => new()
        {
            Exported = false,
            Summary = summary
        };
}