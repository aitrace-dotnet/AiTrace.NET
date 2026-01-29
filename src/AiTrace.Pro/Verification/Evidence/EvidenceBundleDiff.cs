using System.Security.Cryptography;
using System.Text.Json;

namespace AiTrace.Pro.Verification.Evidence;

public static class EvidenceBundleDiff
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    public static EvidenceBundleDiffResult Compare(string bundleDirA, string bundleDirB)
    {
        if (string.IsNullOrWhiteSpace(bundleDirA)) throw new ArgumentNullException(nameof(bundleDirA));
        if (string.IsNullOrWhiteSpace(bundleDirB)) throw new ArgumentNullException(nameof(bundleDirB));

        var a = LoadSeal(bundleDirA);
        var b = LoadSeal(bundleDirB);

        var mapA = a.Files.ToDictionary(x => x.Path, x => x.Sha256, StringComparer.Ordinal);
        var mapB = b.Files.ToDictionary(x => x.Path, x => x.Sha256, StringComparer.Ordinal);

        var added = new List<string>();
        var removed = new List<string>();
        var changed = new List<EvidenceBundleChangedFile>();

        foreach (var kv in mapA)
        {
            if (!mapB.TryGetValue(kv.Key, out var shaB))
            {
                removed.Add(kv.Key);
                continue;
            }

            if (!string.Equals(kv.Value, shaB, StringComparison.OrdinalIgnoreCase))
            {
                changed.Add(new EvidenceBundleChangedFile
                {
                    Path = kv.Key,
                    Sha256A = kv.Value,
                    Sha256B = shaB
                });
            }
        }

        foreach (var kv in mapB)
        {
            if (!mapA.ContainsKey(kv.Key))
                added.Add(kv.Key);
        }

        return new EvidenceBundleDiffResult
        {
            BundleA = Path.GetFullPath(bundleDirA),
            BundleB = Path.GetFullPath(bundleDirB),
            BundleHashA = a.BundleHashSha256,
            BundleHashB = b.BundleHashSha256,
            Added = added.OrderBy(x => x, StringComparer.Ordinal).ToList(),
            Removed = removed.OrderBy(x => x, StringComparer.Ordinal).ToList(),
            Changed = changed.OrderBy(x => x.Path, StringComparer.Ordinal).ToList()
        };
    }

    public static EvidenceBundleDiffResult CompareAuditOnly(string bundleDirA, string bundleDirB)
    {
        var full = Compare(bundleDirA, bundleDirB);

        bool IsAuditPath(string p)
            => p.StartsWith("audit/", StringComparison.OrdinalIgnoreCase)
               && p.EndsWith(".json", StringComparison.OrdinalIgnoreCase);

        var added = full.Added.Where(IsAuditPath).ToList();
        var removed = full.Removed.Where(IsAuditPath).ToList();
        var changed = full.Changed.Where(c => IsAuditPath(c.Path)).ToList();

        return new EvidenceBundleDiffResult
        {
            BundleA = full.BundleA,
            BundleB = full.BundleB,
            BundleHashA = full.BundleHashA,
            BundleHashB = full.BundleHashB,
            Added = added,
            Removed = removed,
            Changed = changed
            // IsIdentical sera automatiquement cohérent
        };
    }

    private static EvidenceSeal LoadSeal(string bundleDir)
    {
        var root = Path.GetFullPath(bundleDir);
        var sealPath = Path.Combine(root, "seal.json");

        if (!Directory.Exists(root))
            throw new DirectoryNotFoundException($"Evidence bundle directory not found: {root}");

        if (!File.Exists(sealPath))
            throw new FileNotFoundException($"seal.json not found in bundle: {sealPath}");

        var json = File.ReadAllText(sealPath);
        var seal = JsonSerializer.Deserialize<EvidenceSeal>(json, JsonOptions);

        if (seal is null)
            throw new InvalidOperationException($"Invalid seal.json (deserialize returned null): {sealPath}");

        if (seal.Files is null)
            seal.Files = new List<EvidenceSealEntry>();

        return seal;
    }
}

public sealed class EvidenceBundleDiffResult
{
    public string BundleA { get; set; } = "";
    public string BundleB { get; set; } = "";

    public string BundleHashA { get; set; } = "";
    public string BundleHashB { get; set; } = "";

    public List<string> Added { get; set; } = new();
    public List<string> Removed { get; set; } = new();
    public List<EvidenceBundleChangedFile> Changed { get; set; } = new();

    public bool IsIdentical =>
        string.Equals(BundleHashA, BundleHashB, StringComparison.OrdinalIgnoreCase) &&
        Added.Count == 0 && Removed.Count == 0 && Changed.Count == 0;
}

public sealed class EvidenceBundleChangedFile
{
    public string Path { get; set; } = "";
    public string Sha256A { get; set; } = "";
    public string Sha256B { get; set; } = "";
}