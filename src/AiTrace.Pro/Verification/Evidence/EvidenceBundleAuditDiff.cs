using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AiTrace.Pro.Verification.Evidence;

/// <summary>
/// Compare two evidence bundles but ONLY audit/*.json files (based on seal.json).
/// Returns added/removed/changed relative paths + a deterministic AuditHashSha256 per bundle.
/// </summary>
public static class EvidenceBundleAuditDiff
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public static EvidenceBundleAuditDiffResult Compare(string bundleDirA, string bundleDirB)
    {
        if (string.IsNullOrWhiteSpace(bundleDirA)) throw new ArgumentNullException(nameof(bundleDirA));
        if (string.IsNullOrWhiteSpace(bundleDirB)) throw new ArgumentNullException(nameof(bundleDirB));

        var sealA = LoadSeal(bundleDirA);
        var sealB = LoadSeal(bundleDirB);

        // Only audit/* entries
        var auditFilesA = sealA.Files
            .Where(f => f.Path.StartsWith("audit/", StringComparison.OrdinalIgnoreCase))
            .Select(f => new EvidenceSealEntry { Path = Normalize(f.Path), Sha256 = (f.Sha256 ?? "").ToLowerInvariant() })
            .OrderBy(f => f.Path, StringComparer.Ordinal)
            .ToList();

        var auditFilesB = sealB.Files
            .Where(f => f.Path.StartsWith("audit/", StringComparison.OrdinalIgnoreCase))
            .Select(f => new EvidenceSealEntry { Path = Normalize(f.Path), Sha256 = (f.Sha256 ?? "").ToLowerInvariant() })
            .OrderBy(f => f.Path, StringComparer.Ordinal)
            .ToList();

        // Deterministic audit-only hash for each bundle:
        // "<path>\n<sha>\n" for each audit entry (same scheme as bundle hash, but filtered to audit/)
        var auditHashA = ComputeAuditHash(auditFilesA);
        var auditHashB = ComputeAuditHash(auditFilesB);

        // Dict for diff (path -> sha)
        var dictA = auditFilesA.ToDictionary(f => f.Path, f => f.Sha256, StringComparer.Ordinal);
        var dictB = auditFilesB.ToDictionary(f => f.Path, f => f.Sha256, StringComparer.Ordinal);

        var added = new List<string>();
        var removed = new List<string>();
        var changed = new List<string>();

        // Added + Changed (B vs A)
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

        // Removed (present in A but not in B)
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
            bundleHashA: sealA.BundleHashSha256 ?? "",
            bundleHashB: sealB.BundleHashSha256 ?? "",
            auditHashA: auditHashA,
            auditHashB: auditHashB,
            added: added,
            removed: removed,
            changed: changed
        );
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
            f.Path = Normalize(f.Path ?? "");
            f.Sha256 ??= "";
        }

        return seal;
    }

    private static string Normalize(string path) => path.Replace('\\', '/');

    private static string ComputeAuditHash(List<EvidenceSealEntry> orderedAuditEntries)
    {
        var sb = new StringBuilder();
        foreach (var e in orderedAuditEntries)
        {
            sb.Append(e.Path).Append('\n');
            sb.Append((e.Sha256 ?? "").ToLowerInvariant()).Append('\n');
        }

        return Sha256Hex(Encoding.UTF8.GetBytes(sb.ToString()));
    }

    private static string Sha256Hex(byte[] data)
    {
        var hash = SHA256.HashData(data);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
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
    }

    public string BundleA { get; }
    public string BundleB { get; }

    // From seal.json (whole bundle)
    public string BundleHashA { get; }
    public string BundleHashB { get; }

    // Deterministic hash of ONLY audit/* entries (path+sha pairs)
    public string AuditHashA { get; }
    public string AuditHashB { get; }

    public List<string> Added { get; }
    public List<string> Removed { get; }
    public List<string> Changed { get; }

    public bool IsIdentical => Added.Count == 0 && Removed.Count == 0 && Changed.Count == 0;
}