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

    public ChainVerifier(SignatureOptions? signatureOptions = null)
    {
        _sig = signatureOptions ?? new SignatureOptions();
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
            .OrderBy(Path.GetFileName)
            .ToArray();

        if (files.Length == 0)
        {
            return VerificationResult.Fail(
                VerificationStatus.NoFiles,
                0,
                $"No audit JSON files found under: {auditDirectory}"
            );
        }

        string? lastHash = null;

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

            // 1) Hash check
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

            // 1.5) Signature check (if present)
            var hasSignature =
                !string.IsNullOrWhiteSpace(record.Signature) &&
                !string.IsNullOrWhiteSpace(record.SignatureAlgorithm);

            if (hasSignature)
            {
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

            // 2) Chain check (if PrevHashSha256 present)
            if (idx > 0 && !string.IsNullOrWhiteSpace(record.PrevHashSha256))
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

            lastHash = record.HashSha256;
        }

        return VerificationResult.Ok();
    }
}
