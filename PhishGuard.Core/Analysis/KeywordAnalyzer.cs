using PhishGuard.Core.Data;
using PhishGuard.Core.Models;
using PhishGuard.Core.Parsing;
using PhishGuard.Core.Text;

namespace PhishGuard.Core.Analysis;

/// <summary>
/// Lightweight brand matching helper shared between analysers.
/// </summary>
public static class BrandDetector
{
    /// <summary>
    /// True when <paramref name="value"/> contains any known brand token.
    /// </summary>
    /// <param name="value">Typically a single host label.</param>
    public static bool MatchesAnyKnownBrand(string value)
    {
        var compact = new string(value.Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();

        return BrandRegistry.BrandTokens.Any(
            token => compact.Contains(token, StringComparison.OrdinalIgnoreCase));
    }
}

/// <summary>
/// Looks for phishing vocabulary in the host and path, and flags risky TLDs.
/// Keywords alone are weak evidence, so they are weighted conservatively and
/// suppressed on genuine brand domains.
/// </summary>
public sealed class KeywordAnalyzer : IUrlAnalyzer
{
    /// <inheritdoc />
    public string Name => "Keywords";

    /// <inheritdoc />
    public void Analyze(ParsedUrl url, AnalysisContext context, List<RiskFinding> findings)
    {
        var hostText = url.UnicodeHost.ToLowerInvariant();
        var tld = ExtractTld(url.Host);

        AnalyzeTld(tld, findings);

        // On a real brand domain, words like "login" are expected and harmless.
        if (BrandRegistry.FindOwningBrand(url.Host) is not null)
        {
            return;
        }

        AnalyzeKeywords(
            hostText,
            SuspiciousKeywords.AuthKeywords,
            "AUTH_KEYWORD",
            "Login/verification wording in the host name",
            "Words like 'login', 'verify' or 'secure' in the domain are a classic " +
            "signal of a page built to collect credentials.",
            Severity.Medium,
            findings);

        AnalyzeKeywords(
            hostText,
            SuspiciousKeywords.UrgencyKeywords,
            "URGENCY_KEYWORD",
            "Threatening or urgent wording in the host name",
            "Phishing pages use words like 'suspended', 'expired' or 'unusual " +
            "activity' to create panic and rush the victim.",
            Severity.Low,
            findings);

        AnalyzeKeywords(
            hostText,
            SuspiciousKeywords.RewardKeywords,
            "REWARD_KEYWORD",
            "Prize or reward wording in the host name",
            "Reward, giveaway and prize language is typical of advance-fee and " +
            "gift-card scam campaigns.",
            Severity.Low,
            findings);

        AnalyzeKeywords(
            hostText,
            SuspiciousKeywords.TheftKeywords,
            "ASSET_THEFT_KEYWORD",
            "Sensitive-asset wording in the host name",
            "References to wallets, seeds, OTPs or card data suggest the page is " +
            "built to steal financial credentials or crypto keys.",
            Severity.Medium,
            findings);
    }

    private static void AnalyzeTld(string tld, List<RiskFinding> findings)
    {
        if (RiskyTlds.IsRisky(tld))
        {
            findings.Add(new RiskFinding(
                "RISKY_TLD",
                "High-abuse top-level domain",
                $"'.{tld}' is a low-cost, lightly moderated TLD that is " +
                "disproportionately used for disposable phishing infrastructure.",
                Severity.Medium));
        }
    }

    private static void AnalyzeKeywords(
        string haystack,
        string[] keywords,
        string code,
        string title,
        string detail,
        Severity severity,
        List<RiskFinding> findings)
    {
        var hits = keywords.Where(k =>
            haystack.Contains(k, StringComparison.OrdinalIgnoreCase)).ToArray();

        if (hits.Length == 0)
        {
            return;
        }

        var preview = string.Join(", ", hits.Take(5));

        findings.Add(new RiskFinding(
            code,
            title,
            $"Matched: {preview}. {detail}",
            severity));
    }

    /// <summary>Extracts the last label of a host as its TLD.</summary>
    private static string ExtractTld(string host)
    {
        var labels = host.Split('.', StringSplitOptions.RemoveEmptyEntries);
        return labels.Length == 0 ? string.Empty : labels[^1];
    }
}

/// <summary>
/// Detects homograph attacks: punycode hosts and mixed-script labels such as
/// "аррӏе.com" (Cyrillic) that render almost identically to a real brand.
/// </summary>
public sealed class HomographAnalyzer : IUrlAnalyzer
{
    /// <inheritdoc />
    public string Name => "Homograph";

    /// <inheritdoc />
    public void Analyze(ParsedUrl url, AnalysisContext context, List<RiskFinding> findings)
    {
        if (url.IsPunycoded)
        {
            findings.Add(new RiskFinding(
                "PUNYCODE_HOST",
                "Host uses punycode encoding",
                $"The host '{url.Host}' is an internationalised domain " +
                $"(decoded: '{url.UnicodeHost}'). IDNs are frequently used to " +
                "impersonate well-known brands.",
                Severity.High));
        }

        foreach (var label in url.UnicodeHost.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!TextAnalysis.HasMixedScripts(label))
            {
                continue;
            }

            findings.Add(new RiskFinding(
                "MIXED_SCRIPT_LABEL",
                "Host mixes different alphabets",
                $"The label '{label}' mixes character sets. Attackers swap a " +
                "single letter from another alphabet so the domain looks " +
                "identical to a legitimate one.",
                Severity.High));

            return;
        }
    }
}