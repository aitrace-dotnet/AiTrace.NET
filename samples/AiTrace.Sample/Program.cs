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

if (args.Contains("--debug"))
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
// MODE: DIFF-AUDIT
// Usage:
//   dotnet run -- diff-audit "<bundleA>" "<bundleB>"
//   dotnet run -- diff-audit --json "<bundleA>" "<bundleB>"
//   dotnet run -- diff-audit --out "<path>" "<bundleA>" "<bundleB>"
//   dotnet run -- diff-audit --json --out "<path>" "<bundleA>" "<bundleB>"
//   dotnet run -- diff-audit --strict "<bundleA>" "<bundleB>"
//   dotnet run -- diff-audit --assert-identical "<bundleA>" "<bundleB>"
//   dotnet run -- diff-audit --assert-append-only "<bundleA>" "<bundleB>"
//   dotnet run -- diff-audit --assert-append-only --quiet "<bundleA>" "<bundleB>"
//
// Exit codes (best/common practice):
//   0  = OK (IDENTICAL; OR APPEND-ONLY satisfied when asserted)
//   10 = EXTENDED (added only) in normal mode
//   20 = ALTERED OR assertion failed OR strict fail
//   2  = usage error
//   3  = runtime error (exception)
// ==============================
if (mode == "diff-audit")
{
    // Flags
    var strictMode = args.Contains("--strict");
    var asJsonMode = args.Contains("--json");
    var assertIdentical = args.Contains("--assert-identical");
    var assertAppendOnly = args.Contains("--assert-append-only");
    var quietMode = args.Contains("--quiet");

    // Optional: --out "<path>"
    string? outputPath = null;
    for (int i = 0; i < args.Length; i++)
    {
        if (args[i] == "--out")
        {
            if (i + 1 >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
            {
                Console.WriteLine("Usage error: --out requires a path argument.");
                Environment.Exit(2);
            }

            outputPath = args[i + 1];
            break;
        }
    }

    // Extract bundle paths: ignore mode token + flags + --out + its value
    var bundlePaths = new List<string>();
    for (int i = 0; i < args.Length; i++)
    {
        var token = args[i];

        if (token == "diff-audit") continue;

        if (token is "--strict" or "--json" or "--assert-identical" or "--assert-append-only" or "--quiet")
            continue;

        if (token == "--out")
        {
            i++; // skip next token (the out path)
            continue;
        }

        // Anything else is treated as a path arg
        bundlePaths.Add(token);
    }

    if (bundlePaths.Count < 2)
    {
        Console.WriteLine("Usage:");
        Console.WriteLine("  dotnet run -- diff-audit \"<bundleA>\" \"<bundleB>\"");
        Console.WriteLine("  dotnet run -- diff-audit --json \"<bundleA>\" \"<bundleB>\"");
        Console.WriteLine("  dotnet run -- diff-audit --out \"<path>\" \"<bundleA>\" \"<bundleB>\"");
        Console.WriteLine("  dotnet run -- diff-audit --json --out \"<path>\" \"<bundleA>\" \"<bundleB>\"");
        Console.WriteLine("  dotnet run -- diff-audit --strict \"<bundleA>\" \"<bundleB>\"");
        Console.WriteLine("  dotnet run -- diff-audit --assert-identical \"<bundleA>\" \"<bundleB>\"");
        Console.WriteLine("  dotnet run -- diff-audit --assert-append-only \"<bundleA>\" \"<bundleB>\"");
        Console.WriteLine("  dotnet run -- diff-audit --assert-append-only --quiet \"<bundleA>\" \"<bundleB>\"");
        Environment.Exit(2);
    }

    var bundleA = bundlePaths[0];
    var bundleB = bundlePaths[1];

    EvidenceBundleAuditDiffResult diffResult;
    try
    {
        diffResult = EvidenceBundleAuditDiff.Compare(bundleA, bundleB);
    }
    catch (Exception ex)
    {
        var err = $"DIFF-AUDIT ERROR ❌ : {ex.GetType().Name} - {ex.Message}";
        Console.WriteLine(err);

        if (!string.IsNullOrWhiteSpace(outputPath))
        {
            try
            {
                var full = Path.GetFullPath(outputPath);
                var dir = Path.GetDirectoryName(full);
                if (!string.IsNullOrWhiteSpace(dir)) Directory.CreateDirectory(dir);
                File.WriteAllText(full, err);
            }
            catch { /* ignore */ }
        }

        Environment.Exit(3);
        return;
    }

    // Outcome classification
    var isIdentical = diffResult.IsIdentical;
    var isExtended = diffResult.Removed.Count == 0 && diffResult.Changed.Count == 0 && diffResult.Added.Count > 0;

    // Decide exit code (assertions override normal mode)
    int exitCode;
    if (assertIdentical)
    {
        // must be identical
        exitCode = isIdentical ? 0 : 20;
    }
    else if (assertAppendOnly)
    {
        // must be identical OR extended
        exitCode = (isIdentical || isExtended) ? 0 : 20;
    }
    else if (strictMode && !isIdentical)
    {
        exitCode = 20;
    }
    else if (isIdentical)
    {
        exitCode = 0;
    }
    else if (isExtended)
    {
        exitCode = 10;
    }
    else
    {
        exitCode = 20;
    }

    // Build output (text or json)
    string output;

    if (asJsonMode)
    {
        var payload = new
        {
            bundleA = diffResult.BundleA,
            bundleB = diffResult.BundleB,
            bundleHashA = diffResult.BundleHashA,
            bundleHashB = diffResult.BundleHashB,
            auditHashA = diffResult.AuditHashA,
            auditHashB = diffResult.AuditHashB,
            added = diffResult.Added,
            removed = diffResult.Removed,
            modified = diffResult.Changed,
            summary = new
            {
                added = diffResult.Added.Count,
                removed = diffResult.Removed.Count,
                modified = diffResult.Changed.Count,
                kind = diffResult.Kind.ToString(),
                severity = diffResult.Severity.ToString(),
                status = (isIdentical ? "IDENTICAL" : isExtended ? "APPEND_ONLY" : "ALTERED"),
                exitCode = exitCode,
                assertedIdentical = assertIdentical,
                assertedAppendOnly = assertAppendOnly,
                strictMode = strictMode,
                quietMode = quietMode
            }
        };

        output = JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true });
    }
    else
    {
        var sb = new StringBuilder();

        sb.AppendLine();
        sb.AppendLine("EVIDENCE DIFF (AUDIT ONLY):");
        sb.AppendLine($" - A: {diffResult.BundleA}");
        sb.AppendLine($" - B: {diffResult.BundleB}");
        sb.AppendLine($" - BundleHashA: {diffResult.BundleHashA}");
        sb.AppendLine($" - BundleHashB: {diffResult.BundleHashB}");
        sb.AppendLine($" - AuditHashA : {diffResult.AuditHashA}");
        sb.AppendLine($" - AuditHashB : {diffResult.AuditHashB}");

        // Status line (nicer when assertions are used)
        if (assertAppendOnly)
        {
            sb.AppendLine((isIdentical || isExtended)
                ? $"STATUS ✅ : audit trail is APPEND-ONLY ({(isIdentical ? "IDENTICAL" : "EXTENDED")})"
                : "STATUS ❌ : audit trail is NOT append-only (ALTERED)");
        }
        else if (assertIdentical)
        {
            sb.AppendLine(isIdentical
                ? "STATUS ✅ : audit trail is IDENTICAL"
                : "STATUS ❌ : audit trail is NOT identical");
        }
        else
        {
            sb.AppendLine(isIdentical
                ? "DIFF OK ✅ : audit folders are identical"
                : "DIFF FOUND ❌ : audit folders differ");
        }

        if (diffResult.Added.Count > 0)
        {
            sb.AppendLine("ADDED:");
            foreach (var p in diffResult.Added) sb.AppendLine($" + {p}");
        }

        if (diffResult.Removed.Count > 0)
        {
            sb.AppendLine("REMOVED:");
            foreach (var p in diffResult.Removed) sb.AppendLine($" - {p}");
        }

        if (diffResult.Changed.Count > 0)
        {
            sb.AppendLine("MODIFIED:");
            foreach (var p in diffResult.Changed) sb.AppendLine($" * {p}");
        }

        sb.AppendLine();
        sb.AppendLine(diffResult.SummaryText);

        if (assertIdentical && !isIdentical)
        {
            sb.AppendLine();
            sb.AppendLine("ASSERTION FAIL ❌");
            sb.AppendLine(" - Required: IDENTICAL");
        }

        if (assertAppendOnly && !(isIdentical || isExtended))
        {
            sb.AppendLine();
            sb.AppendLine("ASSERTION FAIL ❌");
            sb.AppendLine(" - Required: APPEND-ONLY (IDENTICAL or EXTENDED)");
        }

        if (strictMode && !isIdentical)
        {
            sb.AppendLine();
            sb.AppendLine("STRICT FAIL ❌ : strict requires IDENTICAL");
        }

        sb.AppendLine();
        sb.AppendLine($"EXIT CODE: {exitCode}");

        output = sb.ToString();
    }

    // Console output (quiet rules):
    // - quiet: print nothing on success (exitCode == 0), EXCEPT if --json is requested (common expectation)
    if (!(quietMode && exitCode == 0 && !asJsonMode))
    {
        Console.WriteLine(output);
    }

    // Optional: write to file (always writes when --out is provided)
    if (!string.IsNullOrWhiteSpace(outputPath))
    {
        try
        {
            var full = Path.GetFullPath(outputPath);
            var dir = Path.GetDirectoryName(full);
            if (!string.IsNullOrWhiteSpace(dir))
                Directory.CreateDirectory(dir);

            File.WriteAllText(full, output);
        }
        catch (Exception ex)
        {
            // Do not change exit code for output failure.
            Console.WriteLine($"WARN: failed to write --out file: {ex.GetType().Name} - {ex.Message}");
        }
    }

    Environment.Exit(exitCode);
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