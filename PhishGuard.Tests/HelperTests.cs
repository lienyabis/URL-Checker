namespace PhishGuard.Tests;

/// <summary>
/// Unit tests for the pure helper components: edit distance, blocklist
/// matching, URL normalisation edge cases and score behaviour.
/// </summary>
public static class HelperTests
{
    private static void Ok(bool condition, string message) => TestRunner.Check(condition, message);

    private static void Eq<T>(T expected, T actual, string what) =>
        TestRunner.ExpectEqual(expected, actual, what);

    /// <summary>Runs every helper test group.</summary>
    public static void Run()
    {
        Levenshtein();
        Blocklist();
        Normalizer();
        Scoring();
    }

    private static void Levenshtein()
    {
        var d = Core.Text.TextAnalysis.Levenshtein;

        Eq(0, d("paypal", "paypal"), "distance identical");
        Eq(1, d("paypal", "paypa1"), "distance single substitution");
        Eq(1, d("paypal", "paypal1"), "distance single insertion");
        Eq(4, d("", "abcd"), "distance from empty");
        Eq(4, d("abcd", ""), "distance to empty");
        Eq(3, d("kitten", "sitting"), "distance kitten/sitting");
        Eq(2, d("flaw", "lawn"), "distance flaw/lawn");

        // Symmetry: the metric must not depend on argument order.
        Eq(d("github", "gihub"), d("gihub", "github"), "distance is symmetric");
    }

    private static void Blocklist()
    {
        var list = new Core.Data.PhishingBlocklist();

        Ok(list.Count > 0, "built-in seed list should not be empty");

        list.Add("*.badsite.tk");
        list.Add("exactdomain.tk");

        Ok(list.Contains("a.b.badsite.tk"), "wildcard suffix matches subdomains");
        Ok(list.Contains("badsite.tk"), "wildcard suffix matches the base domain");
        Ok(list.Contains("exactdomain.tk"), "exact match works");
        Ok(!list.Contains("notbadsite.tk"), "no false positive on similar name");
        Ok(!list.Contains("google.com"), "legitimate domain not in fresh list");

        Ok(list.Add("second.tk"), "adding a brand new entry returns true");
        Ok(!list.Add("second.tk"), "re-adding the same entry returns false");

        // Comments and hosts-file prefixes must be ignored.
        var path = Path.Combine(Path.GetTempPath(), "phishguard-list-test.txt");
        File.WriteAllLines(path, new[]
        {
            "# a comment",
            "! another comment",
            "127.0.0.1 host-file-entry.tk",
            "0.0.0.0 another-entry.tk",
            "https://full-url-entry.tk/some/path"
        });

        var added = list.LoadFromFile(path);
        Ok(added == 3, $"hosts-format file should add 3 entries, added {added}");
        Ok(list.Contains("host-file-entry.tk"), "hosts-file prefix stripped");
        Ok(list.Contains("another-entry.tk"), "second hosts-file entry stripped");
        Ok(list.Contains("full-url-entry.tk"), "full URL reduced to host");
        Ok(!list.Contains("https://full-url-entry.tk/some/path"), "full URL not stored raw");

        File.Delete(path);
    }

    private static void Normalizer()
    {
        Ok(Core.Parsing.UrlNormalizer.TryParse("https://a.com", out _, out _), "parses a simple URL");
        Ok(Core.Parsing.UrlNormalizer.TryParse("a.com", out var p, out _), "adds missing scheme");
        Ok(p is not null && p.Uri.Scheme == "https", "defaults to https");

        Ok(!Core.Parsing.UrlNormalizer.TryParse("javascript:alert(1)", out _, out _), "rejects javascript scheme");
        Ok(!Core.Parsing.UrlNormalizer.TryParse("data:text/html,<h1>x", out _, out _), "rejects data scheme");
        Ok(!Core.Parsing.UrlNormalizer.TryParse("", out _, out _), "rejects empty input");

        Ok(Core.Parsing.UrlNormalizer.TryParse("https://user@evil.tk/", out var pu, out _), "parses userinfo URL");
        Ok(pu is not null && pu.Host == "evil.tk", "userinfo excluded from host");

        Ok(Core.Parsing.UrlNormalizer.TryParse("https://example.com./x", out var pt, out _), "parses trailing-dot host");
        Ok(pt is not null && pt.Host == "example.com", "trailing dot stripped from host");

        Ok(Core.Parsing.UrlNormalizer.TryParse("HTTP://EXAMPLE.COM", out var pm, out _), "parses uppercase scheme");
        Ok(pm is not null && pm.Host == "example.com", "host lower-cased");

        Ok(Core.Parsing.UrlNormalizer.TryParse("http://192.168.0.1:8080/admin", out var pip, out _), "parses ip:port");
        Ok(pip is not null && pip.IsIpLiteral, "detects IP literal host");

        Ok(Core.Parsing.UrlNormalizer.TryParse("https://xn--80ak6aa92e.com/", out var pidn, out _), "parses punycode host");
        Ok(pidn is not null && pidn.IsPunycoded, "detects punycode label");
        Ok(pidn is not null && pidn.UnicodeHost != pidn.Host, "punycode decodes to unicode");

        Ok(Core.Parsing.UrlNormalizer.TryExtractScheme("https://x.com", out var scheme) && scheme == "https",
            "extracts https scheme");
        Ok(!Core.Parsing.UrlNormalizer.TryExtractScheme("example.com", out _), "no scheme on bare host");
    }

    private static void Scoring()
    {
        var scanner = new Core.Scanning.UrlScanner();

        var clean = scanner.Scan("https://www.wikipedia.org/wiki/Spam");
        Eq(0, clean.Score, "clean URL scores zero");
        Eq(Core.Models.Verdict.Safe, clean.Verdict, "clean URL verdict");

        var bad = scanner.Scan("https://paypal-secure.tk/login");
        Ok(bad.Score is > 0 and <= 100, $"score within 1..100, got {bad.Score}");

        var many = scanner.ScanMany(new[] { "https://a.com", "bad!!", "https://paypal-secure.tk" });
        Eq(3, many.Count, "ScanMany returns one result per input");
        Eq(Core.Models.Verdict.Unknown, many[1].Verdict, "ScanMany reports invalid input");

        // Findings must be sorted most-severe first.
        var findings = bad.Findings.ToList();
        for (var i = 1; i < findings.Count; i++)
        {
            Ok(findings[i - 1].Severity >= findings[i].Severity,
                "findings are ordered by descending severity");
        }

        Ok(Core.Data.RiskyTlds.IsRisky("tk"), ".tk is risky");
        Ok(Core.Data.RiskyTlds.IsRisky("XYZ"), ".xyz is risky (case-insensitive)");
        Ok(!Core.Data.RiskyTlds.IsRisky("com"), ".com is not risky");
        Ok(!Core.Data.RiskyTlds.IsRisky("co.uk"), "uk is not risky");

        Ok(Core.Data.BrandRegistry.FindOwningBrand("login.paypal.com") is not null,
            "subdomain of a real brand resolves to that brand");
        Ok(Core.Data.BrandRegistry.FindOwningBrand("paypal-secure.tk") is null,
            "fake domain is not attributed to PayPal");

        Ok(Core.Data.BrandRegistry.BrandTokens.Contains("paypal"), "paypal token generated");
        Ok(Core.Data.BrandRegistry.BrandTokens.Contains("bankofamerica"),
            "multi-word brand compacted into a token");
    }
}