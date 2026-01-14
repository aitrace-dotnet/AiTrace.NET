using System.Text.Json;
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
     .Select(f => new
     {
         Path = f,
         Name = Path.GetFileName(f)
     })
     // On garde seulement les vrais audits horodatés (YYYYMMDD...)
     .Where(x => !string.IsNullOrEmpty(x.Name) && char.IsDigit(x.Name[0]))
     // Ordre déterministe = ordre chronologique
     .OrderBy(x => x.Name)
     .Select(x => x.Path)
     .ToArray();

        if (files.Length == 0)
        {
            return VerificationResult.Fail(
                VerificationStatus.NoFiles,
                0,
                $"No audit JSON files found under: {auditDirectory}"
            );
        }

        // If strict signatures are required, we must have a SignatureService
        if (_policy.RequireSignatures && _sig.SignatureService is null)
        {
            return VerificationResult.Fail(
                VerificationStatus.SignatureServiceMissing,
                0,
                "Signatures are required by policy but no SignatureService is configured."
            );
        }

        string? lastHash = null;

        bool signatureChecked = false;
        bool signatureValid = true;

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

            // 2) Signature check (policy-aware)
            var hasSignature =
                !string.IsNullOrWhiteSpace(record.Signature) &&
                !string.IsNullOrWhiteSpace(record.SignatureAlgorithm);

            if (_policy.RequireSignatures && !hasSignature)
            {
                signatureChecked = true;
                signatureValid = false;

                return VerificationResult.Fail(
                    VerificationStatus.SignatureRequiredButMissing,
                    idx,
                    $"Signature required but missing in '{fileName}'.",
                    fileName,
                    signatureChecked: true,
                    signatureValid: false
                );
            }

            // If signature exists, verify it (even in relaxed mode)
            if (hasSignature)
            {
                signatureChecked = true;

                if (_sig.SignatureService is null)
                {
                    signatureValid = false;

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

            // 3) Chain check
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
                    // relaxed: verify chain only if PrevHash exists
                    if (!string.IsNullOrWhiteSpace(record.PrevHashSha256) &&
                        !string.Equals(record.PrevHashSha256, lastHash, StringComparison.OrdinalIgnoreCase))
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

            lastHash = record.HashSha256;
        }

        return new VerificationResult
        {
            IsValid = true,
            Status = VerificationStatus.Ok,
            SignatureChecked = signatureChecked || _policy.RequireSignatures,
            SignatureValid = signatureValid
        };
    }

    public ComplianceVerificationSummary VerifySummary(
        string auditDirectory,
        bool signatureRequired = false,
        VerificationScope? scope = null)
    {
        scope ??= VerificationScope.All();

        // Policy override ONLY for summary/export
        var policyToUse = signatureRequired ? VerificationPolicy.Strict() : _policy;

        var result = new ChainVerifier(_sig, policyToUse).Verify(auditDirectory);

        // Scope stats (best-effort)
        int filesCount = 0;
        DateTimeOffset? firstUtc = null;
        DateTimeOffset? lastUtc = null;
        bool anySignaturePresent = false;

        if (Directory.Exists(auditDirectory))
        {
            var files = Directory.GetFiles(auditDirectory, "*.json", SearchOption.AllDirectories)
      .Select(f => new
      {
          Path = f,
          Name = Path.GetFileName(f)
      })
      // On garde seulement les vrais audits horodatés (YYYYMMDD...)
      .Where(x => !string.IsNullOrEmpty(x.Name) && char.IsDigit(x.Name[0]))
      // Ordre déterministe = ordre chronologique
      .OrderBy(x => x.Name)
      .Select(x => x.Path)
      .ToArray();

            foreach (var f in files)
            {
                try
                {
                    var json = File.ReadAllText(f);
                    var record = JsonSerializer.Deserialize<AuditRecord>(json, JsonOptions);
                    if (record is null) continue;

                    if (!scope.Includes(record)) continue;

                    filesCount++;

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
                    // ignore; Verify() already reports parse errors
                }
            }
        }

        return ComplianceSummaryBuilder.FromResult(
            result,
            filesVerified: filesCount,
            firstUtc: firstUtc,
            lastUtc: lastUtc,
            anySignaturePresent: anySignaturePresent,
            signatureRequired: signatureRequired
        );
    }
}