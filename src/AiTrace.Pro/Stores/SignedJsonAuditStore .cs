using System.Text;
using System.Text.Json;
using AiTrace.Pro.Licensing;
using AiTrace.Pro.Signing;

namespace AiTrace.Pro.Stores;

/// <summary>
/// Pro JSON store:
/// - finds PrevHash from previous AUDIT file
/// - computes Hash (including PrevHash)
/// - signs the final hash
/// - writes one JSON file per record
/// </summary>
public sealed class SignedJsonAuditStore : IAuditStore
{
    private readonly string _directory;
    private readonly IAuditSignatureService _signer;

    public SignedJsonAuditStore(
        IAuditSignatureService signer,
        string? directory = null)
    {
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));

        _directory = string.IsNullOrWhiteSpace(directory)
            ? Path.Combine(AppContext.BaseDirectory, "aitrace")
            : directory;

        Directory.CreateDirectory(_directory);
    }

    public async Task WriteAsync(AuditRecord record, CancellationToken ct = default)
    {
        if (record is null) throw new ArgumentNullException(nameof(record));

        // Pro feature => requires a license
        LicenseGuard.EnsureLicensed();

        // 1) Chain hashing: find previous hash (AUDIT files only)
        var prev = TryGetLastHash(_directory);

        // 2) Compute final hash INCLUDING PrevHashSha256
        record.PrevHashSha256 = prev;
        record.HashSha256 = AuditHasher.ComputeRecordHash(record);

        // 3) Sign the final hash
        var signature = _signer.Sign(record.HashSha256);

        // record.Signature is init-only in your model -> immutable copy
        var signed = record with
        {
            Signature = signature,
            SignatureAlgorithm = "RSA-SHA256"
        };

        // 4) Write one file per record
        var fileName = $"{signed.TimestampUtc:yyyyMMdd_HHmmssfff}_{signed.Id}.json";
        var path = Path.Combine(_directory, fileName);

        var json = JsonSerializer.Serialize(signed, new JsonSerializerOptions
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
        // Only consider audit JSON files starting with a digit (YYYYMMDD...)
        // This excludes reports/compliance_report.json etc.
        var lastFile = Directory.GetFiles(auditDir, "*.json", SearchOption.AllDirectories)
            .Select(f => new { Path = f, Name = Path.GetFileName(f) })
            .Where(x =>
                !string.IsNullOrWhiteSpace(x.Name) &&
                char.IsDigit(x.Name[0])
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