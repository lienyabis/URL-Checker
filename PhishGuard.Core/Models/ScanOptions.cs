namespace PhishGuard.Core.Models;

/// <summary>
/// Optional network probes. Disabled by default so that a default scan is fully offline.
/// </summary>
public sealed class ScanOptions
{
    /// <summary>Resolve the host name via DNS. Requires network access.</summary>
    public bool ResolveDns { get; init; }

    /// <summary>Follow HTTP redirects to observe the final destination. Requires network access.</summary>
    public bool FollowRedirects { get; init; }

    /// <summary>User agent used when <see cref="FollowRedirects"/> is enabled.</summary>
    public string UserAgent { get; init; } = "PhishGuard/1.0 (+desktop-url-checker)";
}

/// <summary>
/// Default, offline-only options.
/// </summary>
public static class ScanDefaults
{
    /// <summary>No network access of any kind.</summary>
    public static ScanOptions Offline { get; } = new();
}