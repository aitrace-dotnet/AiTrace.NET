using System.Text;
using System.Text.Json;
using AiTrace;

namespace AiTrace.Pro.Verification;

public static class EvidenceExporter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };

    /// <summary>
    /// Exports a portable evidence bundle.
    /// Steps:
    /// 1) Verify source directory with policy+scope
    /// 2) Copy scoped audit JSON into output/audit
    /// 3) Write compliance reports (txt/json)
    /// 4) Write README.txt + (optional) manifest
    /// </summary>
    public static EvidenceExportResult Export(
        string sourceAuditDirectory,
        ChainVerifier verifier,
        EvidenceExportOptions options)
    {
        if (string.IsNullOrWhiteSpace(sourceAuditDirectory))
            throw new ArgumentNullException(nameof(sourceAuditDirectory));

        if (verifier is null)
            throw new ArgumentNullException(nameof(verifier));

        if (options is null)
            throw new ArgumentNullException(nameof(options));

        // -----------------------
        // Option A: Evidence export is always STRICT (regulator-grade)
        // We do NOT mutate 'options' (init-only). We create effectiveOptions.
        // -----------------------
        var effectiveOptions = new EvidenceExportOptions
        {
            OutputDirectory = options.OutputDirectory,
            AuditFolderName = options.AuditFolderName,
            FailIfOutputNotEmpty = options.FailIfOutputNotEmpty,
            PublicKeyPemPath = options.PublicKeyPemPath,
            WriteManifest = options.WriteManifest,
            Scope = options.Scope,

            // 🔒 Force strict policy for evidence bundles
            Policy = VerificationPolicy.Strict()
        };

        // 1) Verify (scoped) first. If it fails, do not export "evidence" as valid.
        var summary = verifier.VerifySummary(
            auditDirectory: sourceAuditDirectory,
            signatureRequired: effectiveOptions.Policy.RequireSignatures,
            scope: effectiveOptions.Scope
        );

        if (!summary.IsValid)
            return EvidenceExportResult.Fail(summary);

        // 2) Prepare output directory
        var outputDir = Path.GetFullPath(effectiveOptions.OutputDirectory);
        var auditOutDir = Path.Combine(outputDir, effectiveOptions.AuditFolderName);

        Directory.CreateDirectory(outputDir);

        if (effectiveOptions.FailIfOutputNotEmpty)
        {
            var any = Directory.EnumerateFileSystemEntries(outputDir).Any();
            if (any)
                throw new InvalidOperationException($"Output directory is not empty: {outputDir}");
        }

        Directory.CreateDirectory(auditOutDir);

        // 3) Copy scoped audit files (only "real" audit json files: start with digit)
        var includedFiles = CopyScopedAuditFiles(sourceAuditDirectory, auditOutDir, effectiveOptions.Scope);

        // 4) Write compliance reports at bundle root
        var txtReportPath = Path.Combine(outputDir, "compliance_report.txt");
        var jsonReportPath = Path.Combine(outputDir, "compliance_report.json");

        File.WriteAllText(txtReportPath, ComplianceReportWriter.ToTextReport(summary), Encoding.UTF8);

        ComplianceReportJsonExporter.WriteJsonReport(
            sourceAuditDirectory,
            jsonReportPath,
            verifier,
            signatureRequired: effectiveOptions.Policy.RequireSignatures,
            scope: effectiveOptions.Scope
        );

        // 5) Copy public key (optional)
        if (!string.IsNullOrWhiteSpace(effectiveOptions.PublicKeyPemPath))
        {
            if (!File.Exists(effectiveOptions.PublicKeyPemPath))
                throw new InvalidOperationException($"Public key file not found: {effectiveOptions.PublicKeyPemPath}");

            File.Copy(effectiveOptions.PublicKeyPemPath, Path.Combine(outputDir, "public_key.pem"), overwrite: true);
        }

        // 6) README.txt
        var readmePath = Path.Combine(outputDir, "README.txt");
        var readme = EvidenceReadmeWriter.BuildReadmeText(summary, effectiveOptions.Policy, effectiveOptions.Scope);
        File.WriteAllText(readmePath, readme, Encoding.UTF8);

        // 7) Optional manifest
        string? manifestPath = null;
        if (effectiveOptions.WriteManifest)
        {
            manifestPath = Path.Combine(outputDir, "manifest.txt");
            File.WriteAllLines(
                manifestPath,
                includedFiles.Select(Path.GetFileName).Where(n => !string.IsNullOrWhiteSpace(n))!,
                Encoding.UTF8
            );
        }

        return new EvidenceExportResult
        {
            Exported = true,
            OutputDirectory = outputDir,
            AuditDirectory = auditOutDir,
            TextReportPath = txtReportPath,
            JsonReportPath = jsonReportPath,
            ReadmePath = readmePath,
            ManifestPath = manifestPath,
            Summary = summary
        };
    }

    private static List<string> CopyScopedAuditFiles(string sourceAuditDirectory, string auditOutDir, VerificationScope scope)
    {
        var copied = new List<string>();

        var files = Directory.GetFiles(sourceAuditDirectory, "*.json", SearchOption.AllDirectories)
            .Select(f => new { Path = f, Name = Path.GetFileName(f) })
            .Where(x => !string.IsNullOrWhiteSpace(x.Name) && char.IsDigit(x.Name[0])) // only audit records
            .OrderBy(x => x.Name)
            .Select(x => x.Path)
            .ToArray();

        foreach (var file in files)
        {
            var fileName = Path.GetFileName(file);

            AuditRecord? record;
            try
            {
                var json = File.ReadAllText(file);
                record = JsonSerializer.Deserialize<AuditRecord>(json, JsonOptions);
            }
            catch
            {
                // If verification passed, parse errors should not happen here.
                // But we skip to keep export robust.
                continue;
            }

            if (record is null)
                continue;

            if (!scope.Includes(record.TimestampUtc))
                continue;

            var dest = Path.Combine(auditOutDir, fileName);
            File.Copy(file, dest, overwrite: true);
            copied.Add(dest);
        }

        return copied;
    }
}