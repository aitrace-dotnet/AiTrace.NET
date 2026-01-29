using AiTrace;
using AiTrace.Pro;
using AiTrace.Pro.Licensing;
using AiTrace.Pro.Signing;
using AiTrace.Pro.Stores;
using AiTrace.Pro.Verification;
using AiTrace.Pro.Verification.Evidence;

var mode = args.Length > 0 ? args[0].ToLowerInvariant() : "run";

// ==============================
// DEV / DEMO ONLY
// ==============================
LicenseGuard.Mode = LicenseMode.Disabled;

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

Console.WriteLine($"MODE={mode} | ARGS={string.Join(" | ", args)}");

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
// MODE: SEALCHECK (verify seal.json for a bundle)
// Usage: dotnet run -- sealcheck "<path_to_evidence_dir>"
// ==============================
if (mode == "sealcheck")
{
    if (args.Length < 2 || string.IsNullOrWhiteSpace(args[1]))
    {
        Console.WriteLine("Usage: dotnet run -- sealcheck \"C:\\path\\to\\evidence_YYYYMMDD_HHMMSS\"");
        return;
    }

    var evidenceDir = args[1];

    var (ok, reason) = EvidenceBundleSealer.VerifySeal(evidenceDir);

    Console.WriteLine();
    Console.WriteLine("EVIDENCE SEALCHECK:");
    Console.WriteLine($" - Evidence dir: {evidenceDir}");
    Console.WriteLine(ok
        ? "SEALCHECK OK ✅ : seal.json matches bundle contents"
        : $"SEALCHECK FAIL ❌ : {reason}");

    return;
}

// ==============================
// MODE: DIFF (compare 2 sealed bundles - FULL bundle)
// Usage: dotnet run -- diff "<bundleA>" "<bundleB>"
// ==============================
if (mode == "diff")
{
    if (args.Length < 3 || string.IsNullOrWhiteSpace(args[1]) || string.IsNullOrWhiteSpace(args[2]))
    {
        Console.WriteLine("Usage: dotnet run -- diff \"C:\\path\\to\\evidence_A\" \"C:\\path\\to\\evidence_B\"");
        return;
    }

    var a = args[1];
    var b = args[2];

    var diff = EvidenceBundleDiff.Compare(a, b);

    Console.WriteLine();
    Console.WriteLine("EVIDENCE DIFF (FULL BUNDLE):");
    Console.WriteLine($" - A: {diff.BundleA}");
    Console.WriteLine($" - B: {diff.BundleB}");
    Console.WriteLine($" - BundleHashA: {diff.BundleHashA}");
    Console.WriteLine($" - BundleHashB: {diff.BundleHashB}");
    Console.WriteLine(diff.IsIdentical
        ? "DIFF OK ✅ : bundles are identical"
        : "DIFF FOUND ❌ : bundles differ");

    if (diff.Added.Count > 0)
    {
        Console.WriteLine("ADDED:");
        foreach (var p in diff.Added) Console.WriteLine($" + {p}");
    }

    if (diff.Removed.Count > 0)
    {
        Console.WriteLine("REMOVED:");
        foreach (var p in diff.Removed) Console.WriteLine($" - {p}");
    }

    if (diff.Changed.Count > 0)
    {
        Console.WriteLine("CHANGED:");
        foreach (var c in diff.Changed)
            Console.WriteLine($" * {c.Path}\n   A={c.Sha256A}\n   B={c.Sha256B}");
    }

    return;
}

// ==============================
// MODE: DIFF-AUDIT (compare ONLY audit/*.json between 2 sealed bundles)
// Usage:
//   dotnet run -- diff-audit "<bundleA>" "<bundleB>"
//   dotnet run -- diff-audit --strict "<bundleA>" "<bundleB>"
// Exit codes:
//   0  = identical
//   10 = extended (added only, no removed/modified)   [non-strict only]
//   20 = altered (removed and/or modified) OR (strict: anything not identical)
// ==============================
if (mode == "diff-audit")
{
    var strictMode = args.Contains("--strict");

    var paths = args
        .Where(a => a != "diff-audit" && a != "--strict")
        .ToArray();

    if (paths.Length < 2 || string.IsNullOrWhiteSpace(paths[0]) || string.IsNullOrWhiteSpace(paths[1]))
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  dotnet run -- diff-audit \"C:\\path\\to\\evidence_A\" \"C:\\path\\to\\evidence_B\"");
        Console.WriteLine("  dotnet run -- diff-audit --strict \"C:\\path\\to\\evidence_A\" \"C:\\path\\to\\evidence_B\"");
        Environment.Exit(20);
        return;
    }

    var a = paths[0];
    var b = paths[1];

    var diff = EvidenceBundleAuditDiff.Compare(a, b);

    Console.WriteLine();
    Console.WriteLine("EVIDENCE DIFF (AUDIT ONLY):");
    Console.WriteLine($" - A: {diff.BundleA}");
    Console.WriteLine($" - B: {diff.BundleB}");
    Console.WriteLine($" - BundleHashA: {diff.BundleHashA}");
    Console.WriteLine($" - BundleHashB: {diff.BundleHashB}");
    Console.WriteLine($" - AuditHashA : {diff.AuditHashA}");
    Console.WriteLine($" - AuditHashB : {diff.AuditHashB}");

    var isIdentical = diff.IsIdentical;
    var isExtendedOnly = diff.Removed.Count == 0 && diff.Changed.Count == 0 && diff.Added.Count > 0;
    var isAltered = diff.Removed.Count > 0 || diff.Changed.Count > 0;

    Console.WriteLine(isIdentical
        ? "DIFF OK ✅ : audit folders are identical"
        : "DIFF FOUND ❌ : audit folders differ");

    if (diff.Added.Count > 0)
    {
        Console.WriteLine("ADDED:");
        foreach (var p in diff.Added) Console.WriteLine($" + {p}");
    }

    if (diff.Removed.Count > 0)
    {
        Console.WriteLine("REMOVED:");
        foreach (var p in diff.Removed) Console.WriteLine($" - {p}");
    }

    if (diff.Changed.Count > 0)
    {
        Console.WriteLine("CHANGED:");
        foreach (var p in diff.Changed) Console.WriteLine($" * {p}");
    }

    Console.WriteLine();
    Console.WriteLine("SUMMARY:");
    Console.WriteLine($"- {diff.Added.Count} audit record(s) ADDED");
    Console.WriteLine($"- {diff.Removed.Count} audit record(s) REMOVED");
    Console.WriteLine($"- {diff.Changed.Count} audit record(s) MODIFIED");

    int exitCode;

    if (isIdentical)
    {
        Console.WriteLine("=> Audit trail is IDENTICAL ✅");
        exitCode = 0;
    }
    else if (isExtendedOnly)
    {
        Console.WriteLine("=> Audit trail was EXTENDED (no alteration detected) ⚠️");
        exitCode = strictMode ? 20 : 10;
    }
    else // altered (removed/changed) or any other non-identical case
    {
        Console.WriteLine("=> Audit trail was ALTERED ❌");
        exitCode = 20;
    }

    Environment.Exit(exitCode);
    return;
}

// ==============================
// MODE: SEAL (re-seal an existing evidence bundle)
// Usage: dotnet run -- seal "<path_to_evidence_dir>"
// ==============================
if (mode == "seal")
{
    if (args.Length < 2 || string.IsNullOrWhiteSpace(args[1]))
    {
        Console.WriteLine("Usage: dotnet run -- seal \"C:\\path\\to\\evidence_YYYYMMDD_HHMMSS\"");
        return;
    }

    var evidenceDir = args[1];

    var sealPathExisting = EvidenceBundleSealer.WriteSeal(evidenceDir);

    Console.WriteLine();
    Console.WriteLine("EVIDENCE SEAL:");
    Console.WriteLine($" - Evidence dir: {evidenceDir}");
    Console.WriteLine($"SEAL WRITTEN ✅ : {sealPathExisting}");

    return; // ⛔ stop here → no new audit, no new bundle
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
    Policy = policy,
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
// EVIDENCE SEAL (bundle hash)
// ============================================================
var bundleDir = evidence.OutputDirectory;
if (string.IsNullOrWhiteSpace(bundleDir))
    throw new InvalidOperationException("ExportEvidence returned an empty OutputDirectory.");

var sealPath = EvidenceBundleSealer.WriteSeal(bundleDir);
Console.WriteLine($"SEAL WRITTEN: {sealPath}");

// ============================================================
// EVIDENCE RECHECK (of newly exported bundle)
// ============================================================
var evidenceAuditDir2 = Path.Combine(bundleDir, "audit");

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