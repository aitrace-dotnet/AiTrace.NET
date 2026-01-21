using AiTrace;
using AiTrace.Pro;
using AiTrace.Pro.Licensing;
using AiTrace.Pro.Signing;
using AiTrace.Pro.Stores;
using AiTrace.Pro.Verification;

var mode = args.Length > 0 ? args[0].ToLowerInvariant() : "run";

// ==============================
// DEV / DEMO ONLY
// ==============================
LicenseGuard.Mode = LicenseMode.Disabled;
// (en Release, tu enlèves cette ligne ou tu ne la mets jamais)

// ---- Paths ----
var baseDir = AppContext.BaseDirectory;
var auditDir = Path.Combine(baseDir, "aitrace");

// ---- Build verification scope (time range) ----
// Example: verify last 7 days (UTC)
var fromUtc = DateTimeOffset.UtcNow.AddDays(-7);
var toUtc = DateTimeOffset.UtcNow;
var scope = VerificationScope.Between(fromUtc, toUtc);

// ---- Build verifier (integrity + signature) ----
var publicKeyPem = File.ReadAllText(@"C:\temp\aitrace_public.pem");
var sigOpts = new SignatureOptions
{
    SignatureService = new RsaAuditSignatureService(publicKeyPem)
};

var strict = VerificationPolicy.Strict();
var policy = new VerificationPolicy
{
    RequireSignatures = strict.RequireSignatures,
    RequireChainIntegrity = strict.RequireChainIntegrity,
    FailOnMissingFiles = strict.FailOnMissingFiles,
    AllowStartMidChain = true
};

var verifier = new ChainVerifier(sigOpts, policy);

// ==============================
// MODE: RECHECK (no new audit, no new bundle)
// Usage: dotnet run -- recheck "<path_to_evidence_dir>"
// ==============================
if (mode == "recheck")
{
    if (args.Length < 2 || string.IsNullOrWhiteSpace(args[1]))
    {
        Console.WriteLine("Usage: dotnet run -- recheck \"C:\\path\\to\\evidence_YYYYMMDD_HHMMSS\"");
        return;
    }

    var evidenceDir = args[1];
    var evidenceAuditPath = Path.Combine(evidenceDir, "audit");

    var recheckSummary = verifier.VerifySummary(
        auditDirectory: evidenceAuditPath,
        signatureRequired: true,
        scope: VerificationScope.All()
    );

    Console.WriteLine();
    Console.WriteLine("EVIDENCE RECHECK:");
    Console.WriteLine($" - Evidence dir: {evidenceDir}");
    Console.WriteLine(recheckSummary.IsValid
        ? "RECHECK OK ✅ : evidence bundle is intact (no tampering detected)"
        : $"RECHECK FAIL ❌ : {recheckSummary.Status} - {recheckSummary.Reason}");

    return;
}

// ==============================
// NORMAL RUN: log + verify + export
// ==============================

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

// ---- Ensure audit directory exists ----
Directory.CreateDirectory(auditDir);

Console.WriteLine("Logged audit record.");
Console.WriteLine($"Audit directory: {auditDir}");

// ---- Verify summary on the chosen scope ----
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

// ============================================================
// EVIDENCE EXPORT
// ============================================================
var evidenceOptions = new EvidenceExportOptions
{
    OutputDirectory = Path.GetFullPath(
        Path.Combine(auditDir, "..", $"evidence_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}")
    ),
    Scope = scope,
    Policy = policy, // réutilise la même policy
    PublicKeyPemPath = @"C:\temp\aitrace_public.pem",
    FailIfOutputNotEmpty = true,
    WriteManifest = true
};

var evidence = AiTracePro.ExportEvidence(
    sourceAuditDirectory: auditDir,
    verifier: verifier,
    options: evidenceOptions
);

Console.WriteLine();
Console.WriteLine("EVIDENCE EXPORTED:");
Console.WriteLine($" - Bundle dir : {evidence.OutputDirectory}");
Console.WriteLine($" - Audit dir  : {evidence.AuditDirectory}");
Console.WriteLine($" - Report TXT : {evidence.TextReportPath}");
Console.WriteLine($" - Report JSON: {evidence.JsonReportPath}");
Console.WriteLine($" - README     : {evidence.ReadmePath}");
if (!string.IsNullOrWhiteSpace(evidence.ManifestPath))
    Console.WriteLine($" - Manifest   : {evidence.ManifestPath}");

// ============================================================
// EVIDENCE RECHECK (of newly exported bundle)
// ============================================================
var evidenceAuditDir2 = Path.Combine(evidence.OutputDirectory, "audit");

var recheck2 = verifier.VerifySummary(
    auditDirectory: evidenceAuditDir2,
    signatureRequired: true,
    scope: VerificationScope.All()
);

Console.WriteLine();
Console.WriteLine("EVIDENCE RECHECK (new bundle):");
Console.WriteLine(recheck2.IsValid
    ? "RECHECK OK (unexpected if you tampered)"
    : $"RECHECK FAIL: {recheck2.Status} - {recheck2.Reason}");