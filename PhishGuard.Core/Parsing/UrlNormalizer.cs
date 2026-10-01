using System.Globalization;
using System.Text;
using PhishGuard.Core.Models;

namespace PhishGuard.Core.Parsing;

/// <summary>
/// Outcome of turning raw user input into something analysable.
/// </summary>
public sealed class ParsedUrl
{
    /// <summary>Input after trimming and adding a scheme, if one was missing.</summary>
    public required string NormalizedUrl { get; init; }

    /// <summary>The parsed URI.</summary>
    public required Uri Uri { get; init; }

    /// <summary>Lower-case host, or an empty string when the input was not a URL.</summary>
    public required string Host { get; init; }

    /// <summary>Unicode (de-punycoded) form of the host when it is an IDN.</summary>
    public required string UnicodeHost { get; init; }

    /// <summary>True when the host is a bare IP literal rather than a domain name.</summary>
    public bool IsIpLiteral { get; init; }

    /// <summary>True when the host contains a punycode (<c>xn--</c>) label.</summary>
    public bool IsPunycoded { get; init; }

    /// <summary>Path plus query plus fragment, as shown to the user.</summary>
    public string PathAndQuery { get; init; } = string.Empty;
}

/// <summary>
/// Turns messy user input (missing scheme, whitespace, "hxxp" defanging, unicode hosts)
/// into a canonical <see cref="Uri"/> for analysis.
/// </summary>
public static class UrlNormalizer
{
    /// <summary>Schemes that can never represent a normal web page.</summary>
    private static readonly string[] DangerousSchemes =
        { "javascript", "data", "vbscript", "file", "about", "blob" };

    /// <summary>Schemes we treat as ordinary web browsing.</summary>
    private static readonly string[] WebSchemes = { "http", "https" };

    /// <summary>
    /// Attempts to normalise arbitrary input into a <see cref="ParsedUrl"/>.
    /// </summary>
    /// <param name="input">Raw text typed or pasted by the user.</param>
    /// <param name="parsed">Parsed result when successful.</param>
    /// <param name="error">Reason for failure when unsuccessful.</param>
    public static bool TryParse(string? input, out ParsedUrl? parsed, out string? error)
    {
        parsed = null;
        error = null;

        if (string.IsNullOrWhiteSpace(input))
        {
            error = "Input is empty.";
            return false;
        }

        var text = Clean(input);

        if (text.Length == 0)
        {
            error = "Input contains no usable characters.";
            return false;
        }

        // Bare host with no scheme: "example.com/login" -> "https://example.com/login"
        if (!HasScheme(text))
        {
            text = "https://" + text;
        }

        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri))
        {
            error = "Not a valid absolute URL.";
            return false;
        }

        var scheme = uri.Scheme.ToLowerInvariant();

        if (DangerousSchemes.Contains(scheme))
        {
            error = $"Unsupported scheme '{scheme}://'.";
            return false;
        }

        if (!WebSchemes.Contains(scheme))
        {
            error = $"Unsupported scheme '{scheme}://'.";
            return false;
        }

        var host = uri.IdnHost.Length > 0 ? uri.IdnHost : uri.Host;
        host = host.ToLowerInvariant().TrimEnd('.');

        if (host.Length == 0)
        {
            error = "URL has no host.";
            return false;
        }

        // Strip brackets from IPv6 literals so the value compares cleanly.
        if (host.StartsWith('[') && host.EndsWith(']'))
        {
            host = host[1..^1];
        }

        var unicodeHost = DecodeIdn(host);
        var isIpLiteral = System.Net.IPAddress.TryParse(host, out _);
        parsed = new ParsedUrl
        {
            NormalizedUrl = BuildDisplayUrl(uri, host),
            Uri = uri,
            Host = host,
            UnicodeHost = unicodeHost,
            IsIpLiteral = isIpLiteral,
            IsPunycoded = host.Contains("xn--", StringComparison.OrdinalIgnoreCase),
            PathAndQuery = uri.PathAndQuery + uri.Fragment
        };

        return true;
    }

    /// <summary>True when the scheme is a non-web scheme such as <c>javascript:</c>.</summary>
    public static bool IsDangerousScheme(string input) =>
        TryExtractScheme(input, out var scheme) &&
        DangerousSchemes.Contains(scheme);

    /// <summary>
    /// Pulls the scheme out of input without fully parsing it. Returns false when absent.
    /// </summary>
    public static bool TryExtractScheme(string input, out string scheme)
    {
        scheme = string.Empty;
        var idx = input.IndexOf(':');
        if (idx <= 0)
        {
            return false;
        }

        var candidate = input[..idx];
        if (!candidate.All(char.IsLetterOrDigit) || !char.IsLetter(candidate[0]))
        {
            return false;
        }

        scheme = candidate.ToLowerInvariant();
        return true;
    }

    /// <summary>Removes whitespace, quotes and common defanging markers.</summary>
    private static string Clean(string input)
    {
        var sb = new StringBuilder(input.Length);

        foreach (var raw in input.Trim())
        {
            // Drop zero-width and other invisible characters used to break up keywords.
            if (char.IsControl(raw) || raw is '\u200B' or '\u200C' or '\u200D' or '\uFEFF')
            {
                continue;
            }

            sb.Append(raw);
        }

        var cleaned = sb.ToString()
            .Replace("\"", string.Empty, StringComparison.Ordinal)
            .Replace("'", string.Empty, StringComparison.Ordinal)
            .Replace("<", string.Empty, StringComparison.Ordinal)
            .Replace(">", string.Empty, StringComparison.Ordinal);

        // Authors defang links as "hxxp://" or "hxxps[:]//" to break scanners.
        cleaned = cleaned
            .Replace("hxxps", "https", StringComparison.OrdinalIgnoreCase)
            .Replace("hxxp", "http", StringComparison.OrdinalIgnoreCase);

        // "[.]" and "(.)" are defanged dots.
        cleaned = cleaned
            .Replace("[.]", ".", StringComparison.Ordinal)
            .Replace("(.)", ".", StringComparison.Ordinal)
            .Replace("[dot]", ".", StringComparison.OrdinalIgnoreCase);

        // "[://]" and "[:]" are defanged colons.
        cleaned = cleaned
            .Replace("[://]", "://", StringComparison.Ordinal)
            .Replace("[:]", ":", StringComparison.Ordinal);

        return cleaned.Trim();
    }

    /// <summary>True when the text already begins with a scheme-like prefix.</summary>
    private static bool HasScheme(string text)
    {
        if (text.IndexOf("://", StringComparison.Ordinal) > 0)
        {
            return true;
        }

        // "javascript:" style without slashes.
        return TryExtractScheme(text, out var scheme) &&
               !scheme.Contains('.', StringComparison.Ordinal) &&
               scheme.Length > 1;
    }

    /// <summary>Rebuilds a display URL with the canonical lower-case host.</summary>
    private static string BuildDisplayUrl(Uri uri, string host)
    {
        var builder = new UriBuilder(uri)
        {
            Host = host.Contains(':', StringComparison.Ordinal) ? $"[{host}]" : host
        };

        return builder.Uri.AbsoluteUri;
    }

    /// <summary>
    /// Converts a punycode host to its Unicode form so brand-spoofing checks can work on it.
    /// Falls back to the input when the IDN cannot be decoded.
    /// </summary>
    private static string DecodeIdn(string host)
    {
        if (!host.Contains("xn--", StringComparison.OrdinalIgnoreCase))
        {
            return host;
        }

        try
        {
            return new IdnMapping().GetUnicode(host).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            return host;
        }
    }
}
