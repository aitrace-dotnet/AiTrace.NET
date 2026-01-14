using AiTrace.Pro.Licensing;
using AiTrace.Pro.Signing;
using AiTrace.Pro.Verification;

namespace AiTrace.Pro;

public static class AiTracePro
{
    /// <summary>
    /// Backward-compatible: verifies an audit directory using the default public key location
    /// (AppContext.BaseDirectory/aitrace_public.pem) and relaxed verification policy.
    /// </summary>
    public static VerificationResult Verify(string auditDirectory)
    {
        LicenseGuard.EnsureLicensed();

        var publicKeyPath = Path.Combine(AppContext.BaseDirectory, "aitrace_public.pem");

        if (!File.Exists(publicKeyPath))
        {
            return VerificationResult.Fail(
                VerificationStatus.ParseError,
                0,
                $"Public key not found: {publicKeyPath}"
            );
        }

        var publicKeyPem = File.ReadAllText(publicKeyPath);

        var sigOpts = new SignatureOptions
        {
            SignatureService = new RsaAuditSignatureService(publicKeyPem)
        };

        var verifier = new ChainVerifier(sigOpts, VerificationPolicy.Relaxed());
        return verifier.Verify(auditDirectory);
    }

    /// <summary>
    /// New: verifies an audit directory with explicit signature options + verification policy.
    /// Use VerificationPolicy.Strict() for "regulator-grade" verification.
    /// </summary>
    public static VerificationResult Verify(
        string auditDirectory,
        SignatureOptions signatureOptions,
        VerificationPolicy policy)
    {
        LicenseGuard.EnsureLicensed();

        if (signatureOptions is null) throw new ArgumentNullException(nameof(signatureOptions));
        if (policy is null) throw new ArgumentNullException(nameof(policy));

        var verifier = new ChainVerifier(signatureOptions, policy);
        return verifier.Verify(auditDirectory);
    }

    /// <summary>
    /// Convenience: verifies using a PUBLIC KEY PEM FILE path, with a chosen policy.
    /// (Most common use outside the Sample.)
    /// </summary>
    public static VerificationResult VerifyWithPublicKeyPath(
        string auditDirectory,
        string publicKeyPemPath,
        VerificationPolicy? policy = null)
    {
        LicenseGuard.EnsureLicensed();

        if (string.IsNullOrWhiteSpace(publicKeyPemPath))
        {
            return VerificationResult.Fail(
                VerificationStatus.ParseError,
                0,
                "Public key path is empty."
            );
        }

        if (!File.Exists(publicKeyPemPath))
        {
            return VerificationResult.Fail(
                VerificationStatus.ParseError,
                0,
                $"Public key not found: {publicKeyPemPath}"
            );
        }

        var publicKeyPem = File.ReadAllText(publicKeyPemPath);

        var sigOpts = new SignatureOptions
        {
            SignatureService = new RsaAuditSignatureService(publicKeyPem)
        };

        var verifier = new ChainVerifier(sigOpts, policy ?? VerificationPolicy.Relaxed());
        return verifier.Verify(auditDirectory);
    }

    /// <summary>
    /// Regulator-grade default:
    /// - Requires signature on every record
    /// - Requires chain on every record (after the first)
    /// - Uses AppContext.BaseDirectory/aitrace_public.pem
    /// </summary>
    public static VerificationResult VerifyRegulatorDefault(string auditDirectory)
    {
        LicenseGuard.EnsureLicensed();

        var publicKeyPath = Path.Combine(AppContext.BaseDirectory, "aitrace_public.pem");

        if (!File.Exists(publicKeyPath))
        {
            return VerificationResult.Fail(
                VerificationStatus.ParseError,
                0,
                $"Public key not found: {publicKeyPath}"
            );
        }

        var publicKeyPem = File.ReadAllText(publicKeyPath);

        var sigOpts = new SignatureOptions
        {
            SignatureService = new RsaAuditSignatureService(publicKeyPem)
        };

        var verifier = new ChainVerifier(sigOpts, VerificationPolicy.Strict());
        return verifier.Verify(auditDirectory);
    }

    /// <summary>
    /// Verifies the default audit directory (AppContext.BaseDirectory/aitrace) using relaxed policy.
    /// </summary>
    public static VerificationResult VerifyDefault()
    {
        LicenseGuard.EnsureLicensed();

        var auditDir = Path.Combine(AppContext.BaseDirectory, "aitrace");
        return Verify(auditDir);
    }

    /// <summary>
    /// Verifies the default audit directory (AppContext.BaseDirectory/aitrace) using regulator-grade strict policy.
    /// </summary>
    public static VerificationResult VerifyRegulatorDefault()
    {
        LicenseGuard.EnsureLicensed();

        var auditDir = Path.Combine(AppContext.BaseDirectory, "aitrace");
        return VerifyRegulatorDefault(auditDir);
    }
}
