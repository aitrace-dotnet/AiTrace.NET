namespace AiTrace;

public interface IAuditStore
{
    Task WriteAsync(AuditRecord record, CancellationToken ct = default);
}
