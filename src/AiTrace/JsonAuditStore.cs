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

        // One file per record: simple, robust, diffable.
        var fileName = $"{record.TimestampUtc:yyyyMMdd_HHmmss}_{record.Id}.json";
        var path = Path.Combine(_directory, fileName);

        var json = JsonSerializer.Serialize(record, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        await File.WriteAllTextAsync(path, json, Encoding.UTF8, ct).ConfigureAwait(false);
    }
}
