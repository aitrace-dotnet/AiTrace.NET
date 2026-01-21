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
                "AiTrace.Pro requires a valid license for production or compliance usage. " +
                "Forking or modifying the source code does not grant compliance guarantees. " +
                "See https://github.com/aitrace-dotnet/AiTrace.NET for licensing details."
            );

        if (!LicenseValidator.TryValidate(raw, out var _, out var reason))
            throw new InvalidOperationException("AiTrace.Pro license is invalid: " + reason);
    }
}
