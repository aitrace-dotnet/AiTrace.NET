using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AiTrace.Pro.Verification.Evidence;

public static class EvidenceBundleSealer
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    /// <summary>
    /// Creates/overwrites a seal.json in the evidence bundle root.
    /// The seal contains per-file SHA256 + a global BundleHashSha256 computed deterministically.
    /// </summary>
    public static string WriteSeal(string evidenceBundleDirectory)
    {
        if (string.IsNullOrWhiteSpace(evidenceBundleDirectory))
            throw new ArgumentNullException(nameof(evidenceBundleDirectory));

        var root = Path.GetFullPath(evidenceBundleDirectory);

        if (!Directory.Exists(root))
            throw new DirectoryNotFoundException($"Evidence directory not found: {root}");

        var sealPath = Path.Combine(root, "seal.json");

        // 1) Collect all files (deterministic), excluding seal.json itself
        var files = Directory.GetFiles(root, "*", SearchOption.AllDirectories)
            .Where(p => !string.Equals(Path.GetFullPath(p), sealPath, StringComparison.OrdinalIgnoreCase))
            .Select(p => new
            {
                FullPath = p,
                RelPath = NormalizeRelPath(Path.GetRelativePath(root, p))
            })
            .OrderBy(x => x.RelPath, StringComparer.Ordinal)
            .ToList();

        // 2) Compute per-file hashes
        var entries = new List<EvidenceSealEntry>(files.Count);
        foreach (var f in files)
        {
            var bytes = File.ReadAllBytes(f.FullPath);
            var sha = Sha256Hex(bytes);

            entries.Add(new EvidenceSealEntry
            {
                Path = f.RelPath,
                Sha256 = sha
            });
        }

        // 3) Compute bundle hash from the ordered list (stable, independent of JSON formatting)
        // Format: "<path>\n<sha>\n" for each entry, UTF8
        var bundleHash = ComputeBundleHash(entries);

        // 4) Write seal.json
        var seal = new EvidenceSeal
        {
            CreatedUtc = DateTimeOffset.UtcNow,
            Algorithm = "SHA-256",
            BundleHashSha256 = bundleHash,
            Files = entries
        };

        var json = JsonSerializer.Serialize(seal, JsonOptions);
        File.WriteAllText(sealPath, json, Encoding.UTF8);

        return sealPath;
    }

    /// <summary>
    /// Verifies an evidence bundle against its seal.json.
    /// Returns (IsValid, Reason). Never throws.
    /// </summary>
    public static (bool IsValid, string Reason) VerifySeal(string evidenceBundleDirectory)
    {
        if (string.IsNullOrWhiteSpace(evidenceBundleDirectory))
            return (false, "Evidence directory is empty.");

        try
        {
            var root = Path.GetFullPath(evidenceBundleDirectory);

            if (!Directory.Exists(root))
                return (false, $"Evidence directory not found: {root}");

            var sealPath = Path.Combine(root, "seal.json");
            if (!File.Exists(sealPath))
                return (false, $"seal.json not found: {sealPath}");

            EvidenceSeal? seal;
            try
            {
                var sealJson = File.ReadAllText(sealPath, Encoding.UTF8);
                seal = JsonSerializer.Deserialize<EvidenceSeal>(sealJson, JsonOptions);
            }
            catch (Exception ex)
            {
                return (false, $"Failed to read/parse seal.json: {ex.GetType().Name}");
            }

            if (seal is null)
                return (false, "seal.json is invalid (null).");

            if (seal.Files is null || seal.Files.Count == 0)
                return (false, "seal.json contains no files.");

            // 1) Verify per-file hashes
            foreach (var entry in seal.Files)
            {
                if (string.IsNullOrWhiteSpace(entry.Path))
                    return (false, "seal.json has an entry with empty Path.");

                var rel = NormalizeRelPath(entry.Path);
                var full = Path.GetFullPath(Path.Combine(root, rel));

                // Prevent path traversal outside bundle
                if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                    return (false, $"Path traversal detected in seal entry: {entry.Path}");

                if (!File.Exists(full))
                    return (false, $"Missing file: {entry.Path}");

                var actual = Sha256Hex(File.ReadAllBytes(full));
                if (!string.Equals(actual, entry.Sha256, StringComparison.OrdinalIgnoreCase))
                    return (false, $"File hash mismatch: {entry.Path}");
            }

            // 2) Verify bundle hash (deterministic over ordered list)
            var ordered = seal.Files
                .Select(e => new EvidenceSealEntry { Path = NormalizeRelPath(e.Path), Sha256 = e.Sha256 })
                .OrderBy(e => e.Path, StringComparer.Ordinal)
                .ToList();

            var expectedBundleHash = ComputeBundleHash(ordered);

            if (!string.Equals(expectedBundleHash, seal.BundleHashSha256, StringComparison.OrdinalIgnoreCase))
                return (false, "Bundle hash mismatch.");

            return (true, "OK");
        }
        catch (Exception ex)
        {
            // Never crash the caller
            return (false, $"Verification threw: {ex.GetType().Name}");
        }
    }

    private static string ComputeBundleHash(List<EvidenceSealEntry> entries)
    {
        var sb = new StringBuilder();
        foreach (var e in entries)
        {
            sb.Append(NormalizeRelPath(e.Path)).Append('\n');
            sb.Append(e.Sha256).Append('\n');
        }

        return Sha256Hex(Encoding.UTF8.GetBytes(sb.ToString()));
    }

    private static string NormalizeRelPath(string rel)
        => rel.Replace('\\', '/'); // stable across OS

    private static string Sha256Hex(byte[] data)
    {
        var hash = SHA256.HashData(data);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}

public sealed class EvidenceSeal
{
    public DateTimeOffset CreatedUtc { get; set; }
    public string Algorithm { get; set; } = "SHA-256";
    public string BundleHashSha256 { get; set; } = "";
    public List<EvidenceSealEntry> Files { get; set; } = new();
}

public sealed class EvidenceSealEntry
{
    public string Path { get; set; } = "";
    public string Sha256 { get; set; } = "";
}