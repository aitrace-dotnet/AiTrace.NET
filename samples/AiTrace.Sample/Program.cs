using AiTrace;
using AiTrace.Pro;
using AiTrace.Pro.Licensing;
using AiTrace.Pro.Signing;
using AiTrace.Pro.Stores;
using AiTrace.Pro.Verification;
using AiTrace.Pro.Verification.Evidence;
using System.Text;
using System.Text.Json;

// --------------------------------------------------
// Global flags (work for ALL modes)
//   --json           => JSON output to console or file
//   --out "<path>"   => write output to file (txt or json)
// --------------------------------------------------
static bool HasFlag(string[] a, string flag)
    => a.Any(x => string.Equals(x, flag, StringComparison.OrdinalIgnoreCase));

static string? GetOptionValue(string[] a, string option)
{
    for (var i = 0; i < a.Length - 1; i++)
    {
        if (string.Equals(a[i], option, StringComparison.OrdinalIgnoreCase))
            return a[i + 1];
    }
    return null;
}

// Remove global flags so your existing parsing stays clean
static string[] StripGlobalFlags(string[] a)
{
    var list = new List<string>(a.Length);
    for (int i = 0; i < a.Length; i++)
    {
        var cur = a[i];

        if (string.Equals(cur, "--json", StringComparison.OrdinalIgnoreCase))
            continue;

        if (string.Equals(cur, "--out", StringComparison.OrdinalIgnoreCase))
        {
            // skip value too, if present
            if (i + 1 < a.Length) i++;
            continue;
        }

        list.Add(cur);
    }
    return list.ToArray();
}

static void WriteOutput(string text, bool asJson, string? outPath)
{
    if (string.IsNullOrWhiteSpace(outPath))
    {
        Console.WriteLine(text);
        return;
    }

    var full = Path.GetFullPath(outPath);
    Directory.CreateDirectory(Path.GetDirectoryName(full)!);
    File.WriteAllText(full, text, Encoding.UTF8);

    // Optional: still tell user where it went
    Console.WriteLine($"WROTE: {full}");
}

//var mode = args.Length > 0 ? args[0].ToLowerInvariant() : "run";

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

var asJson = HasFlag(args, "--json");
var outPath = GetOptionValue(args, "--out");
var args2 = StripGlobalFlags(args);

var mode = args2.Length > 0 ? args2[0].ToLowerInvariant() : "run";

Console.WriteLine($"MODE={mode} | ARGS={string.Join(" | ", args2)}");

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
// MODE: DIFF-AUDIT
// Usage:
//   dotnet run -- diff-audit "<bundleA>" "<bundleB>"
//   dotnet run -- diff-audit --json "<bundleA>" "<bundleB>"
//   dotnet run -- diff-audit --strict "<bundleA>" "<bundleB>"
// Exit codes:
//   0  = IDENTICAL ✅
//   10 = EXTENDED ⚠️ (added only)
//   30 = ALTERED ❌ (removed/modified, maybe added too)
//   40 = ERROR ❌ (invalid paths / missing seal / parse error)
//   2  = bad CLI usage
// ==============================
if (mode == "diff-audit")
{
    var strictMode = args.Contains("--strict");
    var asJsonMode = args.Contains("--json");

    // take non-flag args as paths (excluding "diff-audit" itself)
    var paths = args
        .Where(a => a != "diff-audit" && a != "--strict" && a != "--json")
        .ToArray();

    if (paths.Length < 2)
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  dotnet run -- diff-audit \"<bundleA>\" \"<bundleB>\"");
        Console.WriteLine("  dotnet run -- diff-audit --json \"<bundleA>\" \"<bundleB>\"");
        Console.WriteLine("  dotnet run -- diff-audit --strict \"<bundleA>\" \"<bundleB>\"");
        Environment.Exit(2);
    }

    var a = paths[0];
    var b = paths[1];

    // ✅ never throws (returns ExitCode=40 on errors)
    var diff = EvidenceBundleAuditDiff.SafeCompare(a, b);

    // ✅ JSON output
    if (asJsonMode)
    {
        var payload = new
        {
            bundleA = diff.BundleA,
            bundleB = diff.BundleB,
            bundleHashA = diff.BundleHashA,
            bundleHashB = diff.BundleHashB,
            auditHashA = diff.AuditHashA,
            auditHashB = diff.AuditHashB,
            added = diff.Added,
            removed = diff.Removed,
            modified = diff.Changed,
            error = diff.ErrorMessage,
            summary = new
            {
                added = diff.Added.Count,
                removed = diff.Removed.Count,
                modified = diff.Changed.Count,
                kind = diff.Kind.ToString(),
                severity = diff.Severity.ToString(),
                exitCode = diff.ExitCode
            }
        };

        var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
        Console.WriteLine(json);

        if (diff.ExitCode == 40) Environment.Exit(40);

        // strict => only identical is ok
        if (strictMode && diff.ExitCode != 0) Environment.Exit(20);

        Environment.Exit(diff.ExitCode);
    }

    // ✅ TEXT output
    Console.WriteLine();
    Console.WriteLine("EVIDENCE DIFF (AUDIT ONLY):");
    Console.WriteLine($" - A: {diff.BundleA}");
    Console.WriteLine($" - B: {diff.BundleB}");
    Console.WriteLine($" - BundleHashA: {diff.BundleHashA}");
    Console.WriteLine($" - BundleHashB: {diff.BundleHashB}");
    Console.WriteLine($" - AuditHashA : {diff.AuditHashA}");
    Console.WriteLine($" - AuditHashB : {diff.AuditHashB}");

    if (!string.IsNullOrWhiteSpace(diff.ErrorMessage))
    {
        Console.WriteLine($"ERROR ❌ : {diff.ErrorMessage}");
        Environment.Exit(40);
    }

    Console.WriteLine(diff.IsIdentical
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
        Console.WriteLine("MODIFIED:");
        foreach (var p in diff.Changed) Console.WriteLine($" * {p}");
    }

    Console.WriteLine();
    Console.WriteLine(diff.SummaryText);

    // Exit codes
    if (strictMode && diff.ExitCode != 0) Environment.Exit(20);
    Environment.Exit(diff.ExitCode);
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