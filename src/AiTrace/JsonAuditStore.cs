using System.Text;
using System.Text.Json;

namespace AiTrace;

public sealed class JsonAuditStore : IAuditStore
{
    private readonly string _directory;

    public JsonAuditStore(string? directory = null)
    {
        _directory = string.IsNullOrWhiteSpace(directory)
            ? Path.Combine(AppContext.BaseDirectory, "aitrace")
            : directory;

        Directory.CreateDirectory(_directory);
    }

    public async Task WriteAsync(AuditRecord record, CancellationToken ct = default)
    {
        if (record is null) throw new ArgumentNullException(nameof(record));

        // 1) Chain hashing: find previous hash (audit files only)
        var prev = TryGetLastHash(_directory);
        record.PrevHashSha256 = prev;

        // 2) Recompute hash INCLUDING PrevHashSha256
        record.HashSha256 = AuditHasher.ComputeRecordHash(record);

        // 3) One file per record
        var fileName = $"{record.TimestampUtc:yyyyMMdd_HHmmss}_{record.Id}.json";
        var path = Path.Combine(_directory, fileName);

        var json = JsonSerializer.Serialize(record, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        await File.WriteAllTextAsync(path, json, Encoding.UTF8, ct)
            .ConfigureAwait(false);
    }

    private static string? TryGetLastHash(string auditDir)
    {
        if (!Directory.Exists(auditDir)) return null;

        // ✅ IMPORTANT:
        // Only consider audit JSON files (starting with YYYYMMDD...)
        // This excludes compliance_report.json, reports/, etc.
        var lastFile = Directory.GetFiles(auditDir, "*.json", SearchOption.AllDirectories)
            .Select(f => new { Path = f, Name = Path.GetFileName(f) })
            .Where(x =>
                !string.IsNullOrWhiteSpace(x.Name) &&
                char.IsDigit(x.Name[0]) // audit files start with date
            )
            .OrderByDescending(x => x.Name) // filename is chronological
            .Select(x => x.Path)
            .FirstOrDefault();

        if (lastFile is null) return null;

        var json = File.ReadAllText(lastFile);

        const string key = "\"HashSha256\":";
        var i = json.IndexOf(key, StringComparison.OrdinalIgnoreCase);
        if (i < 0) return null;

        i += key.Length;
        while (i < json.Length && char.IsWhiteSpace(json[i])) i++;
        if (i >= json.Length || json[i] != '"') return null;
        i++;

        var j = json.IndexOf('"', i);
        if (j < 0) return null;

        var value = json.Substring(i, j - i);
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }
}