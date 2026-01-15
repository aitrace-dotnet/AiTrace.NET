namespace AiTrace.Pro.Licensing;

/// <summary>
/// Controls how AiTrace.Pro licensing is enforced.
/// </summary>
public enum LicenseMode
{
    /// <summary>
    /// Licensing disabled (dev/demo only).
    /// </summary>
    Disabled = 0,

    /// <summary>
    /// Licensing enforced (throws if missing/invalid).
    /// </summary>
    Enforced = 1
}
