using System.Net;
using PhishGuard.Core.Models;
using PhishGuard.Core.Parsing;

namespace PhishGuard.Core.Analysis;

/// <summary>
/// Structural checks that do not depend on any feed: raw IP hosts, deep
/// subdomains, embedded credentials, unusual ports, obfuscation tricks.
/// </summary>
public sealed class StructuralAnalyzer : IUrlAnalyzer
{
    /// <inheritdoc />
    public string Name => "Structural";

    /// <inheritdoc />
    public void Analyze(ParsedUrl url, AnalysisContext context, List<RiskFinding> findings)
    {
        AnalyzeHost(url, findings);
        AnalyzeCredentials(url, findings);
        AnalyzePort(url, findings);
        AnalyzeScheme(url, findings);
        AnalyzePath(url, findings);
    }

    private static void AnalyzeHost(ParsedUrl url, List<RiskFinding> findings)
    {
        if (url.IsIpLiteral)
        {
            var isPrivate = IsPrivateAddress(url.Host);

            findings.Add(new RiskFinding(
                "IP_LITERAL_HOST",
                "Uses a raw IP address instead of a domain name",
                "Legitimate services almost always use a domain name. A bare IP " +
                "address is commonly used by phishing kits and malware " +
                "distribution servers to avoid domain-based blocking" +
                (isPrivate ? ", and this address points at a private/internal network." : "."),
                isPrivate ? Severity.Critical : Severity.High));

            return;
        }

        var labels = url.Host.Split('.', StringSplitOptions.RemoveEmptyEntries);

        // A public suffix in the middle of the host ("paypal.com.evil.tk") means
        // the real domain is the trailing part. Legitimate hosts never do this.
        if (labels.Length >= 4 && IsEmbeddedSuffix(labels))
        {
            findings.Add(new RiskFinding(
                "EMBEDDED_REGISTRABLE_DOMAIN",
                "Real domain hidden behind another domain",
                $"'{url.Host}' contains '{string.Join(".", labels[..^1])}' as a " +
                $"complete domain, but the site is actually served from " +
                $"'{string.Join(".", labels[^2..])}'. Reading only the start of " +
                "the address makes this look trustworthy.",
                Severity.Critical));
        }

        // Five or more labels is a strong sign of subdomain padding.
        if (labels.Length >= 5)
        {
            findings.Add(new RiskFinding(
                "DEEP_SUBDOMAIN",
                "Unusually deep subdomain chain",
                $"The host has {labels.Length} parts ('{url.Host}'). " +
                "Phishing kits hide the real domain at the end of long chains " +
                "such as 'login.paypal.com.secure-update.tk'.",
                labels.Length >= 6 ? Severity.High : Severity.Medium));
        }

        // The left-most label is what the user reads first, so it is the part
        // attackers spoof: "paypal-secure.tk".
        var firstLabel = labels.Length > 0 ? labels[0] : string.Empty;
        var hyphenCount = firstLabel.Count(c => c == '-');
        var digitCount = firstLabel.Count(char.IsDigit);

        if (hyphenCount >= 3 || digitCount >= 3)
        {
            findings.Add(new RiskFinding(
                "NOISY_LABEL",
                "Host label is padded with separators and digits",
                $"'{firstLabel}' contains {hyphenCount} hyphens and {digitCount} digits. " +
                "Machine-generated phishing domains typically look like this.",
                Severity.Medium));
        }

        // Very long host names push the real domain out of view.
        if (url.Host.Length > 50)
        {
            findings.Add(new RiskFinding(
                "LONG_HOST",
                "Unusually long host name",
                $"The host is {url.Host.Length} characters long, which can push the " +
                "true domain outside the visible part of the address bar.",
                Severity.Medium));
        }
    }

    private static void AnalyzeCredentials(ParsedUrl url, List<RiskFinding> findings)
    {
        var userInfo = url.Uri.UserInfo;

        if (userInfo.Length == 0)
        {
            return;
        }

        findings.Add(new RiskFinding(
            "EMBEDDED_CREDENTIALS",
            "URL contains embedded credentials",
            $"The part before '@' ('{userInfo}') is ignored by browsers but looks " +
            "like part of the domain. This is used to confuse people into " +
            "trusting a familiar-looking address.",
            Severity.High));
    }

    private static void AnalyzePort(ParsedUrl url, List<RiskFinding> findings)
    {
        if (url.Uri.IsDefaultPort || url.Uri.Port <= 0)
        {
            return;
        }

        // 8080, 8000, 3000 and friends often front a quick phishing landing page.
        if (url.Uri.Port is 8080 or 8000 or 3000 or 5000 or 8443 or 81 or 8888)
        {
            findings.Add(new RiskFinding(
                "UNUSUAL_PORT",
                "Unusual network port",
                $"Traffic is directed to port {url.Uri.Port}. Throwaway phishing " +
                "pages are commonly served from alternate ports to bypass filters.",
                Severity.Medium));
        }
    }

    private static void AnalyzeScheme(ParsedUrl url, List<RiskFinding> findings)
    {
        if (url.Uri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        findings.Add(new RiskFinding(
            "NO_TLS",
            "Connection is not encrypted",
            "The URL uses plain HTTP, so nothing you submit is protected in " +
            "transit. Real services almost always offer HTTPS.",
            Severity.Medium));
    }

    private static void AnalyzePath(ParsedUrl url, List<RiskFinding> findings)
    {
        var path = url.PathAndQuery;

        // Heavy obfuscation: runs of %-escapes hide the real destination.
        var percentCount = path.Count(c => c == '%');
        if (percentCount >= 5)
        {
            findings.Add(new RiskFinding(
                "OBFUSCATED_PATH",
                "Path is heavily encoded",
                $"The path contains {percentCount} percent-escapes, which is used " +
                "to hide the real target from simple inspection.",
                Severity.Low));
        }

        // Excessive nesting: /a/b/c/d/e/f/... buries the real page.
        var depth = path.Split('/', StringSplitOptions.RemoveEmptyEntries).Length;
        if (depth >= 6)
        {
            findings.Add(new RiskFinding(
                "DEEP_PATH",
                "Unusually long path",
                $"The path is nested {depth} levels deep, which can be used to " +
                "push meaningful content out of view.",
                Severity.Low));
        }
    }

    /// <summary>
    /// True when one of the leading labels looks like a public suffix, which
    /// means a complete domain is embedded inside a longer host name.
    /// </summary>
    /// <param name="labels">All host labels.</param>
    private static bool IsEmbeddedSuffix(string[] labels)
    {
        // Common registrable suffixes. A label equal to one of these appearing
        // before the final position is the giveaway.
        string[] suffixes =
        {
            "com", "net", "org", "edu", "gov", "mil", "int",
            "co", "ac", "or", "ne", "go", "gr", "in", "me", "tv",
            "biz", "info", "io", "dev", "app", "cloud", "online",
            "us", "uk", "ca", "au", "nz", "de", "fr", "es", "it",
            "nl", "be", "ch", "at", "se", "no", "dk", "fi", "pl",
            "br", "mx", "jp", "cn", "in", "ru", "za", "kr", "tr"
        };

        // Ignore the final label itself; only earlier labels are suspicious.
        for (var i = 0; i < labels.Length - 2; i++)
        {
            if (suffixes.Contains(labels[i], StringComparer.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>True when the address belongs to a private or reserved range.</summary>
    private static bool IsPrivateAddress(string host)
    {
        if (!IPAddress.TryParse(host, out var address))
        {
            return false;
        }

        if (IPAddress.IsLoopback(address))
        {
            return true;
        }

        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal;
        }

        var bytes = address.GetAddressBytes();

        return bytes[0] switch
        {
            0 => true,                                         // "this network"
            10 => true,                                        // 10.0.0.0/8
            127 => true,                                       // loopback
            169 when bytes[1] == 254 => true,                  // link-local
            172 when bytes[1] >= 16 && bytes[1] <= 31 => true, // 172.16.0.0/12
            192 when bytes[1] == 168 => true,                  // 192.168.0.0/16
            _ => false
        };
    }
}