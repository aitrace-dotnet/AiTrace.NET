namespace AiTrace.Pro.Licensing;

public static class LicenseGuard
{
    /// <summary>
    /// Global licensing mode. Default:
    /// - DEBUG  => Disabled
    /// - RELEASE => Enforced
    /// </summary>
    public static LicenseMode Mode { get; set; } =
#if DEBUG
        LicenseMode.Disabled;
#else
        LicenseMode.Enforced;
#endif

    /// <summary>
    /// Ensures AiTrace.Pro is licensed depending on current LicenseMode.
    /// </summary>
    public static void EnsureLicensed()
    {
        if (Mode == LicenseMode.Disabled)
            return;

        var raw = LicenseLoader.LoadRawLicense();

        if (raw is null)
            throw new InvalidOperationException(
                "AiTrace.Pro requires a license. " +
                "Set env var AITRACE_PRO_LICENSE or place 'aitrace.license' next to your app.");

        if (!LicenseValidator.TryValidate(raw, out var _, out var reason))
            throw new InvalidOperationException("AiTrace.Pro license is invalid: " + reason);
    }
}
