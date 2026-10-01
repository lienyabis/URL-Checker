using PhishGuard.Core.Data;
using PhishGuard.Core.Models;
using PhishGuard.Core.Parsing;
using PhishGuard.Core.Text;

namespace PhishGuard.Core.Analysis;

/// <summary>
/// Detects brand impersonation: hosts that reference a well-known brand but are
/// not hosted on that brand's real domain, e.g. "paypal-secure.tk".
/// </summary>
public sealed class BrandImpersonationAnalyzer : IUrlAnalyzer
{
    /// <inheritdoc />
    public string Name => "BrandImpersonation";

    /// <inheritdoc />
    public void Analyze(ParsedUrl url, AnalysisContext context, List<RiskFinding> findings)
    {
        // A genuine brand domain cannot be impersonating itself.
        if (BrandRegistry.FindOwningBrand(url.Host) is not null)
        {
            return;
        }

        // Work on the de-punycoded host so "xn--pypal-4ve.com" is caught too.
        var candidates = new[] { url.Host, url.UnicodeHost }
            .Where(h => !string.IsNullOrEmpty(h))
            .Distinct(StringComparer.OrdinalIgnoreCase);

        foreach (var candidate in candidates)
        {
            var normalized = TextAnalysis.NormalizeConfusables(candidate);

            foreach (var brand in BrandRegistry.Brands)
            {
                var hit = MatchBrand(normalized, brand);

                if (hit is not null)
                {
                    findings.Add(new RiskFinding(
                        "BRAND_IMPERSONATION",
                        $"Impersonates {brand.Name}",
                        $"The host contains '{hit}' but is not on " +
                        $"{brand.Name}'s official domain " +
                        $"({string.Join(", ", brand.LegitimateDomains.Take(3))}). " +
                        "Attackers use this pattern to harvest credentials.",
                        Severity.Critical));

                    // One clear brand match is enough; do not spam every finding.
                    return;
                }
            }
        }
    }

    /// <summary>
    /// Returns the token that matched <paramref name="brand"/>, or null.
    /// An exact token match means the brand name sits on a foreign domain.
    /// </summary>
    private static string? MatchBrand(string normalizedHost, Brand brand)
    {
        var hostNoDots = normalizedHost.Replace(".", string.Empty, StringComparison.Ordinal);

        foreach (var token in TokenCandidates(brand))
        {
            if (hostNoDots.Contains(token, StringComparison.OrdinalIgnoreCase))
            {
                return token;
            }
        }

        // Catch near-misses such as "paypa1" or "micros0ft".
        return FindTyposquat(normalizedHost, brand);
    }

    private static IEnumerable<string> TokenCandidates(Brand brand)
    {
        var compact = new string(brand.Name.Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();
        if (compact.Length > 3)
        {
            yield return compact;
        }

        foreach (var word in brand.Name.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            var token = new string(word.Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();
            if (token.Length > 3)
            {
                yield return token;
            }
        }
    }

    /// <summary>
    /// Detects host labels that are one or two edits away from a brand token,
    /// which covers digit-for-letter swaps ("paypa1") and doubled letters.
    /// </summary>
    private static string? FindTyposquat(string normalizedHost, Brand brand)
    {
        foreach (var label in normalizedHost.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            if (label.Length < 5)
            {
                continue;
            }

            foreach (var token in TokenCandidates(brand))
            {
                // Only test tokens of comparable length to keep this cheap.
                if (Math.Abs(label.Length - token.Length) > 2)
                {
                    continue;
                }

                var distance = TextAnalysis.Levenshtein(label, token);
                var tolerance = token.Length <= 6 ? 1 : 2;

                if (distance > 0 && distance <= tolerance)
                {
                    return label;
                }
            }
        }

        return null;
    }
}