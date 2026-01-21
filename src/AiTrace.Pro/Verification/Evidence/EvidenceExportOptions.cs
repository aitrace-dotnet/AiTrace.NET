namespace AiTrace.Pro.Verification;

public sealed class EvidenceExportOptions
{
    /// <summary>
    /// Output directory for the evidence bundle (will be created if missing).
    /// </summary>
    public string OutputDirectory { get; init; } = "evidence_bundle";

    /// <summary>
    /// Folder name inside OutputDirectory where audit JSON files are copied.
    /// Default: "audit"
    /// </summary>
    public string AuditFolderName { get; init; } = "audit";

    /// <summary>
    /// Verification policy used for verification before export.
    /// </summary>
    public VerificationPolicy Policy { get; init; } = VerificationPolicy.Strict();

    /// <summary>
    /// Which records are included in the bundle (time range, etc.).
    /// </summary>
    public VerificationScope Scope { get; init; } = VerificationScope.All();

    /// <summary>
    /// Optional public key path to include in the bundle as public_key.pem.
    /// </summary>
    public string? PublicKeyPemPath { get; init; }

    /// <summary>
    /// If true, export fails when OutputDirectory is not empty.
    /// Useful for CI / evidence immutability.
    /// </summary>
    public bool FailIfOutputNotEmpty { get; init; } = true;

    /// <summary>
    /// If true, writes manifest.txt listing included audit file names.
    /// </summary>
    public bool WriteManifest { get; init; } = true;


}