using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AiTrace.Pro.Licensing;

public static class LicenseValidator
{
    // Format du raw license:
    // BASE64(payloadJson) + "." + BASE64(signature)
    //
    // payloadJson exemple:
    // {"licensee":"Company Inc.","expiresUtc":"2026-12-31T23:59:59Z","plan":"Pro"}

    // IMPORTANT: Replace this placeholder with your real RSA public key before distributing.
    //
    // To generate a key pair:
    //   openssl genrsa -out aitrace_license_private.pem 2048
    //   openssl rsa -in aitrace_license_private.pem -pubout -out aitrace_license_public.pem
    //
    // Then paste the content of aitrace_license_public.pem here.
    //
    // As long as this value contains the word "placeholder", any validation attempt
    // will throw a descriptive exception instead of silently failing.
    private const string PublicKeyPem = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwplaceholderplaceholder
placeholderplaceholderplaceholderplaceholderplaceholderplaceholder
placeholderplaceholderplaceholderplaceholderplaceholderplaceholder
IDAQAB
-----END PUBLIC KEY-----
""";

    public static bool TryValidate(string raw, out LicenseInfo info, out string reason)
    {
        info = new LicenseInfo();
        reason = "";

        if (string.IsNullOrWhiteSpace(raw))
        {
            reason = "Empty license.";
            return false;
        }

        var parts = raw.Split('.', 2);
        if (parts.Length != 2)
        {
            reason = "Invalid license format (expected 'payload.signature').";
            return false;
        }

        byte[] payloadBytes;
        byte[] sigBytes;

        try
        {
            payloadBytes = Convert.FromBase64String(parts[0]);
            sigBytes = Convert.FromBase64String(parts[1]);
        }
        catch
        {
            reason = "Invalid base64 payload/signature.";
            return false;
        }

        // Guard against accidental use of the placeholder key.
        if (PublicKeyPem.Contains("placeholder", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "AiTrace.Pro license validation is using a placeholder RSA public key. " +
                "Generate a real key pair (openssl genrsa / openssl rsa -pubout) and " +
                "replace the PublicKeyPem constant in LicenseValidator.cs before distributing.");
        }

        // Verify signature
        try
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(PublicKeyPem);

            var ok = rsa.VerifyData(
                payloadBytes,
                sigBytes,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);

            if (!ok)
            {
                reason = "Invalid license signature.";
                return false;
            }
        }
        catch (Exception ex)
        {
            reason = "License verification error: " + ex.Message;
            return false;
        }

        // Parse payload
        try
        {
            var payloadJson = Encoding.UTF8.GetString(payloadBytes);
            using var doc = JsonDocument.Parse(payloadJson);
            var root = doc.RootElement;

            var licensee = root.GetProperty("licensee").GetString() ?? "";
            var expiresUtcStr = root.GetProperty("expiresUtc").GetString() ?? "";
            var plan = root.TryGetProperty("plan", out var p) ? (p.GetString() ?? "Pro") : "Pro";

            if (!DateTimeOffset.TryParse(expiresUtcStr, out var exp))
            {
                reason = "Invalid expiresUtc in license payload.";
                return false;
            }

            info = new LicenseInfo
            {
                Licensee = licensee,
                ExpiresUtc = exp.ToUniversalTime(),
                Plan = plan
            };

            if (string.IsNullOrWhiteSpace(info.Licensee))
            {
                reason = "Licensee is empty.";
                return false;
            }

            if (info.IsExpired(DateTimeOffset.UtcNow))
            {
                reason = $"License expired on {info.ExpiresUtc:O}.";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            reason = "Invalid license payload JSON: " + ex.Message;
            return false;
        }
    }
}
