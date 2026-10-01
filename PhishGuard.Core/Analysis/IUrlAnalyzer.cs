using PhishGuard.Core.Models;
using PhishGuard.Core.Parsing;

namespace PhishGuard.Core.Analysis;

/// <summary>
/// A single check that inspects a URL and contributes findings.
/// Analysers are independent and may be run in any order.
/// </summary>
public interface IUrlAnalyzer
{
    /// <summary>Stable identifier used in logs and tests.</summary>
    string Name { get; }

    /// <summary>
    /// Inspects the URL and appends any findings to <paramref name="findings"/>.
    /// </summary>
    /// <param name="url">Parsed URL under analysis.</param>
    /// <param name="context">Shared state such as the blocklist.</param>
    /// <param name="findings">Sink for discovered risk signals.</param>
    void Analyze(ParsedUrl url, AnalysisContext context, List<RiskFinding> findings);
}

/// <summary>
/// Shared, read-only state passed to every analyser during one scan.
/// </summary>
public sealed class AnalysisContext
{
    /// <summary>Known-bad domain list.</summary>
    public required Data.PhishingBlocklist Blocklist { get; init; }

    /// <summary>Scan options controlling optional network probes.</summary>
    public Models.ScanOptions Options { get; init; } = Models.ScanDefaults.Offline;
}