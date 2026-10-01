using PhishGuard.Core.Data;
using PhishGuard.Core.Models;
using PhishGuard.Core.Parsing;

namespace PhishGuard.Core.Analysis;

/// <summary>
/// Checks the URL against the known-bad domain blocklist.
/// A hit here is decisive and produces a <see cref="Verdict.Malicious"/> result.
/// </summary>
public sealed class BlocklistAnalyzer : IUrlAnalyzer
{
    /// <inheritdoc />
    public string Name => "Blocklist";

    /// <inheritdoc />
    public void Analyze(ParsedUrl url, AnalysisContext context, List<RiskFinding> findings)
    {
        var match = context.Blocklist.Match(url.Host);

        if (match is null)
        {
            return;
        }

        findings.Add(new RiskFinding(
            "BLOCKLIST_MATCH",
            "Listed in known-bad domain feed",
            $"The host '{url.Host}' matches blocklist entry '{match}'. " +
            "This domain is associated with phishing or scam activity.",
            Severity.Critical));
    }
}