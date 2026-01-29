using System.Text;
using System.Text.Json;

namespace AiTrace.Pro.Verification.Evidence;

/// <summary>
/// Compare two evidence bundles but ONLY audit/*.json files (based on seal.json).
/// Returns added/removed/changed relative paths + a semantic summary.
/// </summary>
public static class EvidenceBundleAuditDiff
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    /// <summary>
    /// Compare and throw on errors (directory not found, missing seal, invalid JSON, etc.).
    /// </summary>
    public static EvidenceBundleAuditDiffResult Compare(string bundleDirA, string bundleDirB)
    {
        if (string.IsNullOrWhiteSpace(bundleDirA)) throw new ArgumentNullException(nameof(bundleDirA));
        if (string.IsNullOrWhiteSpace(bundleDirB)) throw new ArgumentNullException(nameof(bundleDirB));

        var sealA = LoadSeal(bundleDirA);
        var sealB = LoadSeal(bundleDirB);

        var dictA = sealA.Files
            .Where(f => f.Path.StartsWith("audit/", StringComparison.OrdinalIgnoreCase))
            .ToDictionary(f => f.Path, f => f.Sha256, StringComparer.Ordinal);

        var dictB = sealB.Files
            .Where(f => f.Path.StartsWith("audit/", StringComparison.OrdinalIgnoreCase))
            .ToDictionary(f => f.Path, f => f.Sha256, StringComparer.Ordinal);

        var added = new List<string>();
        var removed = new List<string>();
        var changed = new List<string>();

        // Added + Changed (B relative to A)
        foreach (var kv in dictB)
        {
            if (!dictA.TryGetValue(kv.Key, out var shaA))
            {
                added.Add(kv.Key);
                continue;
            }

            if (!string.Equals(shaA, kv.Value, StringComparison.OrdinalIgnoreCase))
                changed.Add(kv.Key);
        }

        // Removed
        foreach (var kv in dictA)
        {
            if (!dictB.ContainsKey(kv.Key))
                removed.Add(kv.Key);
        }

        added.Sort(StringComparer.Ordinal);
        removed.Sort(StringComparer.Ordinal);
        changed.Sort(StringComparer.Ordinal);

        return new EvidenceBundleAuditDiffResult(
            bundleA: Path.GetFullPath(bundleDirA),
            bundleB: Path.GetFullPath(bundleDirB),
            bundleHashA: sealA.BundleHashSha256,
            bundleHashB: sealB.BundleHashSha256,
            auditHashA: ComputeAuditHash(dictA),
            auditHashB: ComputeAuditHash(dictB),
            added: added,
            removed: removed,
            changed: changed
        );
    }

    /// <summary>
    /// Compare but NEVER throw. If an error occurs, returns a result with ExitCode=40 and ErrorMessage populated.
    /// </summary>
    public static EvidenceBundleAuditDiffResult SafeCompare(string bundleDirA, string bundleDirB)
    {
        try
        {
            return Compare(bundleDirA, bundleDirB);
        }
        catch (Exception ex)
        {
            return EvidenceBundleAuditDiffResult.Error(
                bundleA: bundleDirA,
                bundleB: bundleDirB,
                errorMessage: ex.Message
            );
        }
    }

    private static EvidenceSeal LoadSeal(string bundleDir)
    {
        var root = Path.GetFullPath(bundleDir);

        if (!Directory.Exists(root))
            throw new DirectoryNotFoundException($"Evidence bundle directory not found: {root}");

        var sealPath = Path.Combine(root, "seal.json");
        if (!File.Exists(sealPath))
            throw new FileNotFoundException($"seal.json not found in: {root}", sealPath);

        var json = File.ReadAllText(sealPath);
        var seal = JsonSerializer.Deserialize<EvidenceSeal>(json, JsonOptions);

        if (seal is null)
            throw new InvalidOperationException($"Invalid seal.json in: {root}");

        seal.Files ??= new List<EvidenceSealEntry>();

        foreach (var f in seal.Files)
        {
            f.Path = (f.Path ?? "").Replace('\\', '/');
            f.Sha256 ??= "";
        }

        return seal;
    }

    /// <summary>
    /// Deterministic audit-only hash from (path, sha256) pairs:
    /// "&lt;path&gt;\n&lt;sha&gt;\n" ordered by path (Ordinal), UTF-8, then SHA-256.
    /// </summary>
    private static string ComputeAuditHash(Dictionary<string, string> auditFileHashes)
    {
        var sb = new StringBuilder();

        foreach (var kv in auditFileHashes.OrderBy(k => k.Key, StringComparer.Ordinal))
        {
            sb.Append(kv.Key).Append('\n');
            sb.Append(kv.Value).Append('\n');
        }

        var bytes = Encoding.UTF8.GetBytes(sb.ToString());
        var hash = System.Security.Cryptography.SHA256.HashData(bytes);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

public enum EvidenceAuditDiffKind
{
    Identical = 0,
    Extended = 1, // added only
    Altered = 2   // removed and/or changed (can also include added)
}

public enum EvidenceAuditDiffSeverity
{
    Info = 0,
    Warning = 1,
    Error = 2
}

/// <summary>
/// Lightweight audit-only diff result (no dependency on EvidenceBundleDiffResult internals).
/// </summary>
public sealed class EvidenceBundleAuditDiffResult
{
    public EvidenceBundleAuditDiffResult(
        string bundleA,
        string bundleB,
        string bundleHashA,
        string bundleHashB,
        string auditHashA,
        string auditHashB,
        List<string> added,
        List<string> removed,
        List<string> changed)
    {
        BundleA = bundleA;
        BundleB = bundleB;
        BundleHashA = bundleHashA;
        BundleHashB = bundleHashB;
        AuditHashA = auditHashA;
        AuditHashB = auditHashB;
        Added = added;
        Removed = removed;
        Changed = changed;

        Kind = ComputeKind(Added.Count, Removed.Count, Changed.Count);

        Severity = Kind switch
        {
            EvidenceAuditDiffKind.Identical => EvidenceAuditDiffSeverity.Info,
            EvidenceAuditDiffKind.Extended => EvidenceAuditDiffSeverity.Warning,
            _ => EvidenceAuditDiffSeverity.Error
        };

        // ✅ Exit codes (common & CI-friendly)
        // 0 = identical, 10 = extended, 30 = altered
        ExitCode = Kind switch
        {
            EvidenceAuditDiffKind.Identical => 0,
            EvidenceAuditDiffKind.Extended => 10,
            _ => 30
        };

        SummaryText = BuildSummaryText(Kind, Added.Count, Removed.Count, Changed.Count);
    }

    private EvidenceBundleAuditDiffResult(
        string bundleA,
        string bundleB,
        string errorMessage)
    {
        BundleA = Path.GetFullPath(bundleA ?? "");
        BundleB = Path.GetFullPath(bundleB ?? "");
        BundleHashA = "";
        BundleHashB = "";
        AuditHashA = "";
        AuditHashB = "";
        Added = new List<string>();
        Removed = new List<string>();
        Changed = new List<string>();

        Kind = EvidenceAuditDiffKind.Altered;
        Severity = EvidenceAuditDiffSeverity.Error;

        // ✅ 40 = runtime error (invalid paths, missing seal, etc.)
        ExitCode = 40;
        ErrorMessage = errorMessage;

        SummaryText =
            "SUMMARY:\n" +
            "- ERROR\n" +
            $"=> {errorMessage}";
    }

    public static EvidenceBundleAuditDiffResult Error(string bundleA, string bundleB, string errorMessage)
        => new(bundleA, bundleB, errorMessage);

    public string BundleA { get; }
    public string BundleB { get; }

    // Global bundle hash from seal.json
    public string BundleHashA { get; }
    public string BundleHashB { get; }

    // Deterministic hash of ONLY audit/* entries
    public string AuditHashA { get; }
    public string AuditHashB { get; }

    public List<string> Added { get; }
    public List<string> Removed { get; }
    public List<string> Changed { get; }

    public bool IsIdentical => Added.Count == 0 && Removed.Count == 0 && Changed.Count == 0;

    // ✅ Machine-actionable fields
    public EvidenceAuditDiffKind Kind { get; }
    public EvidenceAuditDiffSeverity Severity { get; }
    public int ExitCode { get; }
    public string SummaryText { get; }
    public string? ErrorMessage { get; }

    private static EvidenceAuditDiffKind ComputeKind(int added, int removed, int changed)
    {
        if (added == 0 && removed == 0 && changed == 0) return EvidenceAuditDiffKind.Identical;
        if (removed == 0 && changed == 0 && added > 0) return EvidenceAuditDiffKind.Extended;
        return EvidenceAuditDiffKind.Altered;
    }

    private static string BuildSummaryText(EvidenceAuditDiffKind kind, int added, int removed, int changed)
    {
        var sb = new StringBuilder();
        sb.AppendLine("SUMMARY:");
        sb.AppendLine($"- {added} audit record(s) ADDED");
        sb.AppendLine($"- {removed} audit record(s) REMOVED");
        sb.AppendLine($"- {changed} audit record(s) MODIFIED");

        sb.Append(kind switch
        {
            EvidenceAuditDiffKind.Identical => "=> Audit trail is IDENTICAL ✅",
            EvidenceAuditDiffKind.Extended => "=> Audit trail was EXTENDED (no alteration detected) ⚠️",
            _ => "=> Audit trail was ALTERED ❌"
        });

        return sb.ToString();
    }
}