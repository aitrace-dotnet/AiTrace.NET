using System.Text;

namespace AiTrace.Pro.Verification;

public static class ComplianceReportExporter
{
    /// <summary>
    /// Generates a compliance verification report and writes it to disk.
    /// </summary>
    public static string WriteTextReport(
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

        var report = ComplianceReportWriter.ToTextReport(summary);

        Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
        File.WriteAllText(outputPath, report, Encoding.UTF8);

        return outputPath;
    }
}