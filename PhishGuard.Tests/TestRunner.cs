using PhishGuard.Core.Models;
namespace PhishGuard.Tests;

/// <summary>
/// Minimal assertion helper and test runner so the suite has no external
/// package dependencies. Reports pass/fail counts and a non-zero exit code
/// when anything fails.
/// </summary>
public static class TestRunner
{
    private static int _passed;
    private static readonly List<string> Failures = new();

    internal static void Check(bool condition, string message)
    {
        if (condition)
        {
            _passed++;
        }
        else
        {
            Failures.Add(message);
            Console.WriteLine("  FAIL " + message);
        }
    }

    internal static void ExpectEqual<T>(T expected, T actual, string what)
    {
        Check(EqualityComparer<T>.Default.Equals(expected, actual),
            $"{what}: expected '{expected}', got '{actual}'");
    }

    private static void Malicious(Core.Scanning.UrlScanner scanner, string url, string expectedCode)
    {
        var r = scanner.Scan(url);
        var hasCode = r.Findings.Any(f => f.Code == expectedCode);

        Check(
            r.Verdict == Core.Models.Verdict.Malicious && hasCode,
            $"[{url}] -> {r.Verdict} (expected MALICIOUS with {expectedCode}); " +
            $"codes: {string.Join(",", r.Findings.Select(f => f.Code))}");
    }

    private static void AtLeast(Core.Scanning.UrlScanner scanner, string url, Core.Models.Verdict minimum)
    {
        var r = scanner.Scan(url);
        Check(r.Verdict >= minimum, $"[{url}] -> {r.Verdict}, expected at least {minimum}");
    }

    private static void Safe(Core.Scanning.UrlScanner scanner, string url)
    {
        var r = scanner.Scan(url);
        Check(
            r.Verdict <= Core.Models.Verdict.Caution,
            $"[{url}] -> {r.Verdict}, expected SAFE/CAUTION; " +
            $"codes: {string.Join(",", r.Findings.Select(f => f.Code))}");
    }

    private static void Invalid(Core.Scanning.UrlScanner scanner, string url)
    {
        var r = scanner.Scan(url);
        Check(!r.IsValid, $"[{url}] should be invalid but returned {r.Verdict}");
    }

    private static void NormalizesTo(Core.Scanning.UrlScanner scanner, string input, string expectedHost)
    {
        var r = scanner.Scan(input);
        Check(r.Host == expectedHost, $"[{input}] -> host '{r.Host}', expected '{expectedHost}'");
    }

    /// <summary>Runs the full suite and returns a process exit code.</summary>
    public static int Run()
    {
        var scanner = new Core.Scanning.UrlScanner();

        Console.WriteLine("PhishGuard detection test suite");
        Console.WriteLine(new string('=', 72));

        Console.WriteLine("-- must be flagged MALICIOUS --");
        Malicious(scanner, "http://paypal-secure.tk/login", "BRAND_IMPERSONATION");
        Malicious(scanner, "https://login-paypal-verify.xyz/webscr", "BRAND_IMPERSONATION");
        Malicious(scanner, "http://192.168.1.50/login.php", "IP_LITERAL_HOST");
        Malicious(scanner, "http://127.0.0.1/admin", "IP_LITERAL_HOST");
        Malicious(scanner, "https://secure-login-verify.tk/account", "BLOCKLIST_MATCH");
        Malicious(scanner, "https://webscr-paypal-secure.tk/", "BLOCKLIST_MATCH");
        Malicious(scanner, "http://paypal.com.secure-update.tk/", "EMBEDDED_REGISTRABLE_DOMAIN");
        Malicious(scanner, "https://login.microsoft.com.security-alert.net/", "BRAND_IMPERSONATION");
        Malicious(scanner, "https://xn--80ak6aa92e.com/", "PUNYCODE_HOST");

        Console.WriteLine("-- must be flagged, at least suspicious --");
        AtLeast(scanner, "http://micros0ft-support.top/login", Core.Models.Verdict.Suspicious);
        AtLeast(scanner, "http://appleid-apple.com.evil.ga/verify", Core.Models.Verdict.Malicious);
        AtLeast(scanner, "http://secure-banking-alert.click/", Core.Models.Verdict.Malicious);
        AtLeast(scanner, "http://free-gift-card-generator.cfd/claim", Core.Models.Verdict.Malicious);
        AtLeast(scanner, "http://account-suspended-now.ml/", Core.Models.Verdict.Malicious);

        Console.WriteLine("-- legitimate sites must not be flagged --");
        Safe(scanner, "https://www.google.com/search?q=test");
        Safe(scanner, "https://github.com/anthropics/claude-code");
        Safe(scanner, "https://paypal.com/signin");
        Safe(scanner, "https://login.microsoftonline.com/common");
        Safe(scanner, "https://www.microsoft.com/en-gb");
        Safe(scanner, "https://stackoverflow.com/questions/1");
        Safe(scanner, "https://en.wikipedia.org/wiki/Phishing");
        Safe(scanner, "https://www.amazon.co.uk/dp/B0TEST");
        Safe(scanner, "https://github.com/microsoft/vscode/issues");
        Safe(scanner, "https://docs.microsoft.com/azure/active-directory");

        Console.WriteLine("-- malformed input --");
        Invalid(scanner, "");
        Invalid(scanner, "   ");
        Invalid(scanner, "javascript:alert(document.cookie)");
        Invalid(scanner, "not a url at all");
        Invalid(scanner, "file:///C:/Windows/System32/cmd.exe");

        Console.WriteLine("-- normalisation --");
        NormalizesTo(scanner, "paypal.com/login", "paypal.com");
        NormalizesTo(scanner, "  https://Example.COM/Path  ", "example.com");
        NormalizesTo(scanner, "hxxps://evil[.]tk/login", "evil.tk");

        Console.WriteLine("-- helper functions --");
        HelperTests.Run();

        Console.WriteLine("-- labels and scoring helpers --");
        ExpectEqual("SAFE", Core.Models.Verdict.Safe.ToLabel(), "Verdict label");
        ExpectEqual("CRIT", Core.Models.Severity.Critical.ToTag(), "Severity tag");
        ExpectEqual(0, Core.Models.Severity.Info.ToPoints(), "Info points");
        ExpectEqual(55, Core.Models.Severity.Critical.ToPoints(), "Critical points");

        Console.WriteLine();
        Console.WriteLine(new string('=', 72));
        Console.WriteLine($"Passed: {_passed}   Failed: {Failures.Count}");

        if (Failures.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("FAILURES:");
            foreach (var f in Failures)
            {
                Console.WriteLine("  - " + f);
            }

            return 1;
        }

        Console.WriteLine("All tests passed.");
        return 0;
    }
}