using AiTrace;
using AiTrace.Pro.Licensing;
using AiTrace.Pro.Signing;
using AiTrace.Pro.Stores;
using AiTrace.Pro.Verification;

// ==============================
// DEV / DEMO ONLY
// ==============================
LicenseGuard.Mode = LicenseMode.Disabled;
// (en Release, tu enlèves cette ligne ou tu ne la mets jamais)

// ---- Configure AiTrace (Pro signing store) ----
AiTrace.AiTrace.Configure(o =>
{
    o.StoreContent = true;
    o.BasicRedaction = true;

    var privateKeyPem = File.ReadAllText(@"C:\temp\aitrace_private.pem");
    var signer = new RsaAuditSignatureService(privateKeyPem);

    // Pro store: computes PrevHash + Hash, then signs, then writes JSON files
    o.Store = new SignedJsonAuditStore(signer);
});

// ---- Log one decision ----
var decision = new AiDecision
{
    Prompt = "Summarize: The quick brown fox jumps over the lazy dog.",
    Output = "A fox jumps over a dog.",
    Model = "demo-model",
    UserId = "user-123",
    Metadata = new Dictionary<string, object?>
    {
        ["Feature"] = "Demo",
        ["CorrelationId"] = Guid.NewGuid().ToString("n")
    }
};

await AiTrace.AiTrace.LogDecisionAsync(decision);

// ---- Paths ----
var baseDir = AppContext.BaseDirectory;
var auditDir = Path.Combine(baseDir, "aitrace");

Console.WriteLine("Logged audit record.");
Console.WriteLine($"Audit directory: {auditDir}");

// ---- Build verification scope (time range) ----
// Example: verify last 7 days (UTC)
var fromUtc = DateTimeOffset.UtcNow.AddDays(-7);
var toUtc = DateTimeOffset.UtcNow;
var scope = VerificationScope.Between(fromUtc, toUtc);

// ---- Verify (integrity + signature) ----
var publicKeyPem = File.ReadAllText(@"C:\temp\aitrace_public.pem");
var sigOpts = new SignatureOptions
{
    SignatureService = new RsaAuditSignatureService(publicKeyPem)
};

// ✅ Policy for regulators:
// - signatures required
// - chain required
// - BUT allow verifying a time range that starts mid-directory (common in real audits)
var strict = VerificationPolicy.Strict();

// IMPORTANT: VerificationPolicy is a class, not a record -> no "with { }"
var policy = new VerificationPolicy
{
    RequireSignatures = strict.RequireSignatures,
    RequireChainIntegrity = strict.RequireChainIntegrity,
    FailOnMissingFiles = strict.FailOnMissingFiles,

    // new setting
    AllowStartMidChain = true
};

var verifier = new ChainVerifier(sigOpts, policy);

// ✅ Verify summary on the chosen scope
var summary = verifier.VerifySummary(
    auditDir,
    signatureRequired: true,
    scope: scope
);

Console.WriteLine(summary.IsValid
    ? "VERIFY OK (integrity + signature verified)"
    : $"VERIFY FAIL: {summary.Reason}");

Console.WriteLine($"SUMMARY: Status={summary.Status}, Files={summary.FilesVerified}, Signature={summary.SignatureStatus}");
Console.WriteLine($"SCOPE (UTC): {fromUtc:O} to {toUtc:O}");

// ---- Export compliance report to disk (scoped) ----
// Put reports in a subfolder so they don't pollute audit root
var reportsDir = Path.Combine(auditDir, "reports");
Directory.CreateDirectory(reportsDir);

var reportPath = Path.Combine(reportsDir, "compliance_report.txt");

ComplianceReportExporter.WriteTextReport(
    auditDir,
    reportPath,
    verifier,
    signatureRequired: true,
    scope: scope
);

Console.WriteLine($"Compliance report written to: {reportPath}");

var jsonReportPath = Path.Combine(reportsDir, "compliance_report.json");

ComplianceReportJsonExporter.WriteJsonReport(
    auditDir,
    jsonReportPath,
    verifier,
    signatureRequired: true,
    scope: scope
);

Console.WriteLine($"Compliance JSON report written to: {jsonReportPath}");