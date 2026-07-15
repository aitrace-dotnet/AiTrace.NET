using System.Text;
using System.Text.Json;
using AiTrace.Pro.Licensing;
using AiTrace.Pro.Signing;

namespace AiTrace.Pro.Stores;

/// <summary>
/// Pro JSON store:
/// - finds PrevHash from the previous audit file
/// - computes the record hash (including PrevHash)
/// - signs the final hash with the configured RSA key
/// - writes one JSON file per record
/// </summary>
public sealed class SignedJsonAuditStore : IAuditStore
{
    private readonly string _directory;
    private readonly IAuditSignatureService _signer;

    // Ensures only one write happens at a time per store instance
    // (prevents two concurrent writes from reading the same PrevHash).
    private readonly SemaphoreSlim _writeLock = new(1, 1);

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

        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // 1) Chain hashing: find previous hash (audit files only)
            var prev = TryGetLastHash(_directory);

            // 2) Compute final hash INCLUDING PrevHashSha256
            record.PrevHashSha256 = prev;
            record.HashSha256 = AuditHasher.ComputeRecordHash(record);

            // 3) Sign the final hash
            var signature = _signer.Sign(record.HashSha256);

            // record.Signature is init-only -> create an immutable copy with signature
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
        finally
        {
            _writeLock.Release();
        }
    }

    private static string? TryGetLastHash(string auditDir)
    {
        if (!Directory.Exists(auditDir)) return null;

        // Only consider audit JSON files starting with a digit (YYYYMMDD...).
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

        try
        {
            var json = File.ReadAllText(lastFile);
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("HashSha256", out var prop))
            {
                var value = prop.GetString();
                return string.IsNullOrWhiteSpace(value) ? null : value;
            }
        }
        catch
        {
            // Corrupt or unreadable last file — start a new chain.
        }

        return null;
    }
}
