using System.Text.Json;
using AiTrace;
using AiTrace.Pro.Signing;

namespace AiTrace.Pro.Verification;

public sealed class ChainVerifier
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    private readonly SignatureOptions _sig;
    private readonly VerificationPolicy _policy;

    public ChainVerifier(SignatureOptions? signatureOptions = null, VerificationPolicy? policy = null)
    {
        _sig = signatureOptions ?? new SignatureOptions();
        _policy = policy ?? VerificationPolicy.Relaxed();
    }

    public VerificationResult Verify(string auditDirectory)
    {
        if (string.IsNullOrWhiteSpace(auditDirectory))
        {
            return VerificationResult.Fail(
                VerificationStatus.ParseError,
                0,
                "Audit directory is empty."
            );
        }

        if (!Directory.Exists(auditDirectory))
        {
            return VerificationResult.Fail(
                VerificationStatus.DirectoryNotFound,
                0,
                $"Audit directory not found: {auditDirectory}"
            );
        }

        var files = Directory.GetFiles(auditDirectory, "*.json", SearchOption.AllDirectories)
            .OrderBy(Path.GetFileName) // stable, deterministic
            .ToArray();

        if (files.Length == 0)
        {
            return VerificationResult.Fail(
                VerificationStatus.NoFiles,
                0,
                $"No audit JSON files found under: {auditDirectory}"
            );
        }

        // ✅ Signature policy sanity check (strict mode)
        // If signatures are required, we must have a SignatureService to verify them.
        if (_policy.RequireSignatures && _sig.SignatureService is null)
        {
            return VerificationResult.Fail(
                VerificationStatus.SignatureServiceMissing,
                0,
                "Signatures are required by policy but no SignatureService is configured."
            );
        }

        string? lastHash = null;

        bool signatureChecked = false; // did we attempt verification?
        bool signatureValid = true;     // remains true if no invalid signature is found

        for (int idx = 0; idx < files.Length; idx++)
        {
            var file = files[idx];
            var fileName = Path.GetFileName(file);

            AuditRecord? record;
            try
            {
                var json = File.ReadAllText(file);
                record = JsonSerializer.Deserialize<AuditRecord>(json, JsonOptions);
            }
            catch (Exception ex)
            {
                return VerificationResult.Fail(
                    VerificationStatus.ParseError,
                    idx,
                    $"Failed to read/parse '{fileName}': {ex.Message}",
                    fileName
                );
            }

            if (record is null)
            {
                return VerificationResult.Fail(
                    VerificationStatus.ParseError,
                    idx,
                    $"Invalid JSON record in '{fileName}'.",
                    fileName
                );
            }

            // 1) Record hash integrity
            var expected = AuditHasher.ComputeRecordHash(record);
            if (!string.Equals(record.HashSha256, expected, StringComparison.OrdinalIgnoreCase))
            {
                return VerificationResult.Fail(
                    VerificationStatus.HashMismatch,
                    idx,
                    $"Hash mismatch in '{fileName}'. Expected {expected} but found {record.HashSha256 ?? "(null)"}.",
                    fileName
                );
            }

            // 2) Signature policy + signature verification
            var hasSignature =
                !string.IsNullOrWhiteSpace(record.Signature) &&
                !string.IsNullOrWhiteSpace(record.SignatureAlgorithm);

            if (_policy.RequireSignatures && !hasSignature)
            {
                return VerificationResult.Fail(
                    VerificationStatus.SignatureRequiredButMissing,
                    idx,
                    $"Signature required but missing in '{fileName}'.",
                    fileName,
                    signatureChecked: true,
                    signatureValid: false
                );
            }

            // If the record has a signature, verify it (even in relaxed mode)
            if (hasSignature)
            {
                signatureChecked = true;

                if (_sig.SignatureService is null)
                {
                    return VerificationResult.Fail(
                        VerificationStatus.SignatureServiceMissing,
                        idx,
                        $"Signature present in '{fileName}' but no SignatureService configured.",
                        fileName,
                        signatureChecked: true,
                        signatureValid: false
                    );
                }

                var ok = _sig.SignatureService.Verify(record.HashSha256, record.Signature!);
                if (!ok)
                {
                    signatureValid = false;

                    return VerificationResult.Fail(
                        VerificationStatus.SignatureInvalid,
                        idx,
                        $"Signature invalid in '{fileName}'.",
                        fileName,
                        signatureChecked: true,
                        signatureValid: false
                    );
                }
            }

            // 3) Chain policy + chain check
            if (idx > 0)
            {
                if (_policy.RequireChainIntegrity)
                {
                    if (string.IsNullOrWhiteSpace(record.PrevHashSha256))
                    {
                        return VerificationResult.Fail(
                            VerificationStatus.ChainBroken,
                            idx,
                            $"Chain integrity required but PrevHashSha256 is missing in '{fileName}'.",
                            fileName
                        );
                    }

                    if (!string.Equals(record.PrevHashSha256, lastHash, StringComparison.OrdinalIgnoreCase))
                    {
                        return VerificationResult.Fail(
                            VerificationStatus.ChainBroken,
                            idx,
                            $"Chain broken at '{fileName}'. PrevHashSha256={record.PrevHashSha256} but previous hash was {lastHash}.",
                            fileName
                        );
                    }
                }
                else
                {
                    // relaxed: verify chain only if PrevHash is present
                    if (!string.IsNullOrWhiteSpace(record.PrevHashSha256))
                    {
                        if (!string.Equals(record.PrevHashSha256, lastHash, StringComparison.OrdinalIgnoreCase))
                        {
                            return VerificationResult.Fail(
                                VerificationStatus.ChainBroken,
                                idx,
                                $"Chain broken at '{fileName}'. PrevHashSha256={record.PrevHashSha256} but previous hash was {lastHash}.",
                                fileName
                            );
                        }
                    }
                }
            }

            lastHash = record.HashSha256;
        }

        // ✅ All good
        // If signatures were required, consider them "checked"
        if (_policy.RequireSignatures)
        {
            signatureChecked = true;
            signatureValid = true;
        }

        return new VerificationResult
        {
            IsValid = true,
            Status = VerificationStatus.Ok,
            SignatureChecked = signatureChecked,
            SignatureValid = signatureValid
        };
    }

    public ComplianceVerificationSummary VerifySummary(string auditDirectory, bool signatureRequired = false)
    {
        // ✅ Policy override ONLY for summary/exports
        var policy = signatureRequired
            ? VerificationPolicy.Strict()
            : _policy;

        var result = new ChainVerifier(_sig, policy).Verify(auditDirectory);

        // Scope stats (best-effort)
        int filesVerified = 0;
        DateTimeOffset? firstUtc = null;
        DateTimeOffset? lastUtc = null;
        bool anySignaturePresent = false;

        if (Directory.Exists(auditDirectory))
        {
            var files = Directory.GetFiles(auditDirectory, "*.json", SearchOption.AllDirectories)
                .OrderBy(Path.GetFileName)
                .ToArray();

            filesVerified = files.Length;

            foreach (var f in files)
            {
                try
                {
                    var json = File.ReadAllText(f);
                    var record = JsonSerializer.Deserialize<AuditRecord>(json, JsonOptions);
                    if (record is null) continue;

                    if (firstUtc is null || record.TimestampUtc < firstUtc) firstUtc = record.TimestampUtc;
                    if (lastUtc is null || record.TimestampUtc > lastUtc) lastUtc = record.TimestampUtc;

                    if (!string.IsNullOrWhiteSpace(record.Signature) &&
                        !string.IsNullOrWhiteSpace(record.SignatureAlgorithm))
                    {
                        anySignaturePresent = true;
                    }
                }
                catch
                {
                    // ignore: Verify() already returns exact errors; this is best-effort scope
                }
            }
        }

        return ComplianceSummaryBuilder.FromResult(
            result,
            filesVerified: filesVerified,
            firstUtc: firstUtc,
            lastUtc: lastUtc,
            anySignaturePresent: anySignaturePresent,
            signatureRequired: signatureRequired
        );
    }
}