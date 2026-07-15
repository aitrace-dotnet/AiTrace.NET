using System.Reflection;
using System.Text.Json.Serialization;
using AiTrace;
using AiTrace.Api.Dtos;
using AiTrace.Pro.Licensing;
using AiTrace.Pro.Signing;
using AiTrace.Pro.Stores;
using AiTrace.Pro.Verification;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(o =>
{
    o.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "AiTrace API",
        Version = "v1"
    });
});

// JSON options
builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
});

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

// -----------------------
// Config (appsettings)
// -----------------------
var cfg = app.Configuration.GetSection("AiTraceApi");
var auditRoot = cfg["AuditRoot"] ?? "aitrace";
var privateKeyPath = cfg["PrivateKeyPath"];
var publicKeyPath = cfg["PublicKeyPath"];

// Audit directory: always rooted at app base dir (prevents path traversal)
var baseDir = AppContext.BaseDirectory;
var auditDir = Path.GetFullPath(Path.Combine(baseDir, auditRoot));

// ✅ Hard guard: auditDir MUST be under baseDir
var baseDirFull = Path.GetFullPath(baseDir);
if (!auditDir.StartsWith(baseDirFull, StringComparison.OrdinalIgnoreCase))
    throw new InvalidOperationException($"AuditRoot must stay under app base directory. Computed: {auditDir}");

Directory.CreateDirectory(auditDir);

// -----------------------
// DEV ONLY: license mode
// -----------------------
// ⚠️ Pour démo/dev: désactiver le guard de licence en local.
// Mets ça seulement ici (API), pas dans la lib.
LicenseGuard.Mode = LicenseMode.Disabled;

// -----------------------
// Configure AiTrace
// -----------------------
AiTrace.AiTrace.Configure(o =>
{
    o.StoreContent = true;
    o.BasicRedaction = true;

    if (string.IsNullOrWhiteSpace(privateKeyPath) || !File.Exists(privateKeyPath))
        throw new InvalidOperationException($"Private key file not found: {privateKeyPath}");

    var privateKeyPem = File.ReadAllText(privateKeyPath);
    var signer = new RsaAuditSignatureService(privateKeyPem);

    // writes JSON into ./aitrace (next to app) + prevhash + hash + signature
    o.Store = new SignedJsonAuditStore(signer, auditDir);
});

// -----------------------
// Endpoints
// -----------------------

app.MapGet("/", () => Results.Redirect("/swagger"));

// ✅ 0) Health
app.MapGet("/health", () =>
{
    var asm = Assembly.GetExecutingAssembly();
    var version = asm.GetName().Version?.ToString() ?? "unknown";

    return Results.Ok(new
    {
        Status = "Ok",
        Service = "AiTrace.Api",
        Version = version,
        UtcNow = DateTimeOffset.UtcNow,
        AuditDirectory = auditDir
    });
});

// 1) Log decision
app.MapPost("/api/decisions", async (DecisionDto dto) =>
{
    if (string.IsNullOrWhiteSpace(dto.Prompt))
        return Results.BadRequest("Prompt is required.");

    if (string.IsNullOrWhiteSpace(dto.Output))
        return Results.BadRequest("Output is required.");

    var decision = new AiDecision
    {
        Prompt = dto.Prompt,
        Output = dto.Output,
        Model = dto.Model,
        UserId = dto.UserId,
        Metadata = dto.Metadata ?? new Dictionary<string, object?>()
    };

    await AiTrace.AiTrace.LogDecisionAsync(decision);

    return Results.Ok(new
    {
        Message = "Logged audit record.",
        AuditDirectory = auditDir
    });
});

// 2) Verify + (optionally) export reports
app.MapPost("/api/verify", (VerifyRequest req) =>
{
    if (string.IsNullOrWhiteSpace(publicKeyPath) || !File.Exists(publicKeyPath))
        return Results.Problem($"Public key file not found: {publicKeyPath}");

    var publicKeyPem = File.ReadAllText(publicKeyPath);
    var sigOpts = new SignatureOptions
    {
        SignatureService = new RsaAuditSignatureService(publicKeyPem)
    };

    // Policy (default strict)
    var policy = req.Policy?.ToVerificationPolicy() ?? VerificationPolicy.Strict();

    var verifier = new ChainVerifier(sigOpts, policy);

    // Scope (default all)
    var scope = req.Scope?.ToScope() ?? VerificationScope.All();

    // Verify summary (scoped)
    var summary = verifier.VerifySummary(
        auditDirectory: auditDir,
        signatureRequired: policy.RequireSignatures,
        scope: scope
    );

    // Optional: export reports to ./aitrace/reports
    if (req.ExportReports)
    {
        var reportsDir = Path.Combine(auditDir, "reports");
        Directory.CreateDirectory(reportsDir);

        var txtPath = Path.Combine(reportsDir, "compliance_report.txt");
        ComplianceReportExporter.WriteTextReport(
            auditDir,
            txtPath,
            verifier,
            signatureRequired: policy.RequireSignatures,
            scope: scope
        );

        var jsonPath = Path.Combine(reportsDir, "compliance_report.json");
        ComplianceReportJsonExporter.WriteJsonReport(
            auditDir,
            jsonPath,
            verifier,
            signatureRequired: policy.RequireSignatures,
            scope: scope
        );
    }

    return Results.Ok(summary);
});

// 3) Get latest reports
app.MapGet("/api/reports/text", () =>
{
    var path = Path.Combine(auditDir, "reports", "compliance_report.txt");
    if (!File.Exists(path))
        return Results.NotFound("No text report found. Run /api/verify with ExportReports=true.");

    return Results.Text(File.ReadAllText(path), "text/plain");
});

app.MapGet("/api/reports/json", () =>
{
    var path = Path.Combine(auditDir, "reports", "compliance_report.json");
    if (!File.Exists(path))
        return Results.NotFound("No JSON report found. Run /api/verify with ExportReports=true.");

    return Results.Text(File.ReadAllText(path), "application/json");
});

app.Run();

// DTOs are in separate files under AiTrace.Api/Dtos/