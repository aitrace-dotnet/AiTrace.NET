using AiTrace.Pro.Licensing;
using AiTrace.Pro.Signing;

namespace AiTrace.Pro.Stores;

/// <summary>
/// Pro wrapper store: signs each audit record hash before persisting.
/// Keeps AiTrace (free) independent from Pro.
/// </summary>
public sealed class SignedAuditStore : IAuditStore
{
    private readonly IAuditStore _inner;
    private readonly IAuditSignatureService _signer;

    public SignedAuditStore(IAuditStore inner, IAuditSignatureService signer)
    {
        _inner = inner ?? throw new ArgumentNullException(nameof(inner));
        _signer = signer ?? throw new ArgumentNullException(nameof(signer));
    }

    public async Task WriteAsync(AuditRecord record, CancellationToken ct = default)
    {
        if (record is null) throw new ArgumentNullException(nameof(record));

        // Pro feature => requires a license
        LicenseGuard.EnsureLicensed();

        if (string.IsNullOrWhiteSpace(record.HashSha256))
            throw new InvalidOperationException("AuditRecord.HashSha256 must be computed before signing.");

        // Sign the final hash (stable, format-independent)
        var signature = _signer.Sign(record.HashSha256);

        // AuditRecord is a 'record' => easy immutable copy with signature fields set
        var signed = record with
        {
            Signature = signature,
            SignatureAlgorithm = "RSA-SHA256"
        };

        await _inner.WriteAsync(signed, ct).ConfigureAwait(false);
    }
}
