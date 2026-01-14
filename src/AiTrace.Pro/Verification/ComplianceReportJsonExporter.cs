using System.Text.Json;

namespace AiTrace.Pro.Verification;

public static class ComplianceReportJsonExporter
{
    /// <summary>
    /// Generates a compliance verification report (JSON) and writes it to disk.
    /// </summary>
    public static string WriteJsonReport(
        string auditDirectory,
        string outputPath,
        ChainVerifier verifier,
        bool signatureRequired = true,
        VerificationScope? scope = null)
    {
        if (verifier is null) throw new ArgumentNullException(nameof(verifier));

        var summary = verifier.VerifySummary(
            auditDirectory,
            signatureRequired: signatureRequired,
            scope: scope
        );

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);

        var json = JsonSerializer.Serialize(summary, new JsonSerializerOptions
        {
            WriteIndented = true
        });

        File.WriteAllText(outputPath, json);

        return outputPath;
    }
}