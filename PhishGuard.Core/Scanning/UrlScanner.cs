using PhishGuard.Core.Analysis;
using PhishGuard.Core.Data;
using PhishGuard.Core.Models;
using PhishGuard.Core.Parsing;

namespace PhishGuard.Core.Scanning;

/// <summary>
/// Runs every <see cref="IUrlAnalyzer"/> over a URL and turns the collected
/// findings into a score and a verdict.
/// </summary>
public sealed class UrlScanner
{
    private readonly IReadOnlyList<IUrlAnalyzer> _analyzers;
    private readonly PhishingBlocklist _blocklist;

    /// <summary>Creates a scanner with the built-in analysers and seed blocklist.</summary>
    public UrlScanner()
        : this(new PhishingBlocklist(), DefaultAnalyzers())
    {
    }

    /// <summary>Creates a scanner with a custom blocklist and analyser set.</summary>
    /// <param name="blocklist">Known-bad domain list to check against.</param>
    /// <param name="analyzers">Analysers to execute, in order.</param>
    public UrlScanner(PhishingBlocklist blocklist, IEnumerable<IUrlAnalyzer> analyzers)
    {
        _blocklist = blocklist;
        _analyzers = analyzers.ToArray();
    }

    /// <summary>The analyser pipeline used by the default constructor.</summary>
    public static IReadOnlyList<IUrlAnalyzer> DefaultAnalyzers() => new IUrlAnalyzer[]
    {
        new BlocklistAnalyzer(),
        new BrandImpersonationAnalyzer(),
        new HomographAnalyzer(),
        new StructuralAnalyzer(),
        new KeywordAnalyzer()
    };

    /// <summary>
    /// Analyses a single URL. Never throws for bad user input.
    /// </summary>
    /// <param name="url">Raw URL text.</param>
    /// <param name="options">Optional network probe settings.</param>
    public ScanResult Scan(string? url, ScanOptions? options = null)
    {
        var effective = options ?? ScanDefaults.Offline;

        if (!UrlNormalizer.TryParse(url, out var parsed, out var error) || parsed is null)
        {
            return ScanResult.Failure(url ?? string.Empty, error ?? "Invalid URL.");
        }

        var context = new AnalysisContext
        {
            Blocklist = _blocklist,
            Options = effective
        };

        var findings = new List<RiskFinding>();

        foreach (var analyzer in _analyzers)
        {
            try
            {
                analyzer.Analyze(parsed, context, findings);
            }
            catch (Exception ex)
            {
                // A failing analyser must never break the whole scan.
                findings.Add(new RiskFinding(
                    "ANALYZER_ERROR",
                    $"Analyser '{analyzer.Name}' failed",
                    ex.Message,
                    Severity.Info));
            }
        }

        // Optional DNS probe, only when explicitly enabled by the caller.
        if (effective.ResolveDns && !parsed.IsIpLiteral)
        {
            DnsProbe.AppendDnsFinding(parsed.Host, findings);
        }

        var ordered = findings
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Code, StringComparer.Ordinal)
            .ToArray();

        return new ScanResult
        {
            Input = url ?? string.Empty,
            NormalizedUrl = parsed.NormalizedUrl,
            Host = parsed.Host,
            Verdict = ScoreVerdict(ordered),
            Score = ComputeScore(ordered),
            Findings = ordered,
            ScannedAt = DateTimeOffset.UtcNow
        };
    }

    /// <summary>Analyses many URLs, preserving input order.</summary>
    /// <param name="urls">Raw URL texts.</param>
    /// <param name="options">Optional network probe settings.</param>
    public IReadOnlyList<ScanResult> ScanMany(IEnumerable<string?> urls, ScanOptions? options = null) =>
        urls.Select(u => Scan(u, options)).ToArray();

    /// <summary>
    /// Sums severity points, capped at 100. Repeated signals from the same
    /// analyser family are damped so one noisy URL cannot reach 100 by itself.
    /// </summary>
    private static int ComputeScore(IReadOnlyList<RiskFinding> findings)
    {
        var raw = 0;
        var seenCodes = new Dictionary<string, int>(StringComparer.Ordinal);

        foreach (var finding in findings)
        {
            seenCodes.TryGetValue(finding.Code, out var count);

            // Halve the contribution of each repeat of the same signal.
            var points = finding.Severity.ToPoints();
            raw += points / (1 + count);

            seenCodes[finding.Code] = count + 1;
        }

        return Math.Clamp(raw, 0, 100);
    }

    /// <summary>Maps the set of findings onto a final verdict.</summary>
    private static Verdict ScoreVerdict(IReadOnlyList<RiskFinding> findings)
    {
        if (findings.Count == 0)
        {
            return Verdict.Safe;
        }

        // A critical finding is decisive regardless of the numeric score.
        if (findings.Any(f => f.Severity == Severity.Critical))
        {
            return Verdict.Malicious;
        }

        var score = ComputeScore(findings);

        if (findings.Any(f => f.Severity == Severity.High))
        {
            return Verdict.Suspicious;
        }

        if (score >= 30)
        {
            return Verdict.Suspicious;
        }

        return score >= 10 ? Verdict.Caution : Verdict.Safe;
    }
}