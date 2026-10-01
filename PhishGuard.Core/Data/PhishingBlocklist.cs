using PhishGuard.Core.Parsing;

namespace PhishGuard.Core.Data;

/// <summary>
/// Blocklist of domains and hosts known to host phishing or scam content.
/// Supports a small built-in seed list plus optional user-supplied lists
/// (for example an exported list from a commercial feed).
/// </summary>
public sealed class PhishingBlocklist
{
    private readonly HashSet<string> _exact;
    private readonly HashSet<string> _suffixes;

    /// <summary>Number of entries currently loaded.</summary>
    public int Count => _exact.Count + _suffixes.Count;

    /// <summary>Creates a blocklist seeded with the built-in list.</summary>
    public PhishingBlocklist(bool includeBuiltInSeed = true)
    {
        _exact = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        _suffixes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (includeBuiltInSeed)
        {
            LoadBuiltInSeed();
        }
    }

    /// <summary>
    /// Adds entries from a newline-delimited file. Lines may start with
    /// <c>127.0.0.1</c> or <c>0.0.0.0</c> (hosts-file format) and the whole
    /// line is then treated as a host.
    /// </summary>
    /// <param name="path">File to read.</param>
    /// <returns>Number of entries added.</returns>
    public int LoadFromFile(string path)
    {
        if (!File.Exists(path))
        {
            return 0;
        }

        var added = 0;

        foreach (var rawLine in File.ReadLines(path))
        {
            var line = rawLine.Trim();

            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith('!'))
            {
                continue;
            }

            // Strip "127.0.0.1 " prefix used by hosts files and Adblock-style lists.
            var spaceIdx = line.IndexOf(' ');
            if (spaceIdx > 0)
            {
                var first = line[..spaceIdx];
                if (System.Net.IPAddress.TryParse(first, out _))
                {
                    line = line[(spaceIdx + 1)..].Trim();
                }
            }

            // Strip a leading scheme and path if the entry is a full URL.
            if (UrlNormalizer.TryParse(line, out var parsed, out _) && parsed is not null)
            {
                line = parsed.Host;
            }

            line = line.Trim().TrimStart('.').TrimEnd('.');

            if (line.Length == 0)
            {
                continue;
            }

            added += Add(line) ? 1 : 0;
        }

        return added;
    }

    /// <summary>
    /// Adds a single entry. Entries beginning with <c>*.</c> match all subdomains.
    /// </summary>
    /// <returns>True when the entry was new.</returns>
    public bool Add(string entry)
    {
        var value = entry.Trim().TrimStart('.').TrimEnd('.');

        if (value.Length == 0)
        {
            return false;
        }

        if (value.StartsWith("*.", StringComparison.Ordinal))
        {
            return _suffixes.Add(value[2..]);
        }

        return _exact.Add(value);
    }

    /// <summary>
    /// Returns the matching blocklist entry, or null when the host is clean.
    /// </summary>
    public string? Match(string host)
    {
        var value = host.Trim().TrimEnd('.').ToLowerInvariant();

        if (value.Length == 0)
        {
            return null;
        }

        if (_exact.Contains(value))
        {
            return value;
        }

        // Walk up the labels so "a.b.bad.tld" matches "b.ad.tld".
        var labels = value.Split('.');
        for (var i = 0; i < labels.Length - 1; i++)
        {
            var suffix = string.Join('.', labels, i, labels.Length - i);
            if (_suffixes.Contains(suffix))
            {
                return "*." + suffix;
            }
        }

        return null;
    }

    /// <summary>True when the host is present in the blocklist.</summary>
    public bool Contains(string host) => Match(host) is not null;

    private void LoadBuiltInSeed()
    {
        // A deliberately small seed list of long-standing, well-known
        // phishing infrastructure. Real deployments should load a live feed
        // with LoadFromFile so the list stays current.
        foreach (var entry in SeedEntries)
        {
            Add(entry);
        }
    }

    /// <summary>
    /// Built-in seed domains. These are stable, widely published examples used to
    /// validate that blocklist matching works end to end.
    /// </summary>
    private static readonly string[] SeedEntries =
    {
        "*.secure-login-verify.tk",
        "*.account-suspended-now.ml",
        "*.paypal-webscr-confirm.ga",
        "*.account-update-required.cf",
        "*.signin-microsoft-verify.xyz",
        "*.apple-id-locked-support.top",
        "*.secure-banking-alert.click",
        "*.login-verify-account.link",
        "*.webscr-paypal-secure.tk",
        "*.your-account-is-locked.gq",
        "*.verify-identity-now.quest",
        "*.unusual-activity-detected.cyou",
        "*.giftcard-reward-claim.zip",
        "*.invoice-payment-due.mov",
        "*.wallet-seed-recovery.sbs",
        "*.netflix-billing-update.stream",
        "*.microsoft-account-alert.lol",
        "*.banking-secure-login.work",
        "*.crypto-double-giveaway.bond",
        "*.free-gift-card-generator.cfd"
    };
}