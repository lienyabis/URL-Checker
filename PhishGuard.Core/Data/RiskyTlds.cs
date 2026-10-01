namespace PhishGuard.Core.Data;

/// <summary>
/// Top-level domains that are heavily abused for phishing and are rarely
/// seen on established, legitimate consumer services.
/// </summary>
public static class RiskyTlds
{
    /// <summary>Free-registration TLDs with very low cost and near-zero moderation.</summary>
    private static readonly HashSet<string> Free = new(StringComparer.OrdinalIgnoreCase)
    {
        "tk", "ml", "ga", "cf", "gq", "top", "xyz", "zip", "mov", "click", "link",
        "work", "country", "kim", "science", "party", "gdn", "review", "stream",
        "download", "loan", "racings", "win", "bid", "date", "faith", "racing",
        "cricket", "men", "webcam", "cam", "surf", "quest", "cfd", "sbs", "buzz"
    };

    /// <summary>TLDs frequently used for disposable or throwaway phishing pages.</summary>
    private static readonly HashSet<string> Disposables = new(StringComparer.OrdinalIgnoreCase)
    {
        "rest", "monster", "quest", "cyou", "icu", "sbs", "buzz", "monster", "lol",
        "autos", "boats", "bar", "beauty", "bond", "cfd", "dental", "fit", "hair",
        "info", "kim", "loan", "men", "money", "pics", "pictures", "porn", "run",
        "shoes", "shop", "site", "space", "store", "top", "trade", "win", "work"
    };

    /// <summary>Newer gTLDs that see a lot of brand-abuse registrations.</summary>
    private static readonly HashSet<string> BrandAbuse = new(StringComparer.OrdinalIgnoreCase)
    {
        "co", "io", "me", "cc", "tv", "app", "dev", "cloud", "online", "site",
        "tech", "store", "shop", "website", "space", "fun", "live", "life", "world"
    };

    /// <summary>Returns true when the TLD is a known high-abuse TLD.</summary>
    public static bool IsRisky(string tld) =>
        !string.IsNullOrEmpty(tld) &&
        (Free.Contains(tld) || Disposables.Contains(tld));

    /// <summary>Returns true when the TLD is newer and commonly abused for brand impersonation.</summary>
    public static bool IsBrandAbuseProne(string tld) =>
        !string.IsNullOrEmpty(tld) && BrandAbuse.Contains(tld);
}