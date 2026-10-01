namespace PhishGuard.Core.Models;

/// <summary>
/// Complete outcome of checking one URL.
/// </summary>
public sealed class ScanResult
{
    /// <summary>Exactly what the user typed.</summary>
    public required string Input { get; init; }

    /// <summary>Canonical URL that was analysed, or null when parsing failed.</summary>
    public string? NormalizedUrl { get; init; }

    /// <summary>Host that was analysed, or an empty string when parsing failed.</summary>
    public string Host { get; init; } = string.Empty;

    /// <summary>Final classification.</summary>
    public required Verdict Verdict { get; init; }

    /// <summary>Risk score from 0 (clean) to 100 (maximally risky).</summary>
    public required int Score { get; init; }

    /// <summary>Every risk signal detected, ordered most severe first.</summary>
    public required IReadOnlyList<RiskFinding> Findings { get; init; }

    /// <summary>When the scan ran, in UTC.</summary>
    public required DateTimeOffset ScannedAt { get; init; }

    /// <summary>Human readable explanation of the verdict.</summary>
    public string Summary
    {
        get
        {
            if (Verdict == Verdict.Malicious)
            {
                // Only claim a confirmed list hit when one actually occurred.
                var listed = Findings.Any(f => f.Code == "BLOCKLIST_MATCH");

                return listed
                    ? "This link matches known malicious infrastructure. Do not open it."
                    : "This link matches known phishing patterns. Do not open it.";
            }

            return Verdict switch
            {
                Verdict.Suspicious => "Several strong phishing indicators were found. Do not sign in.",
                Verdict.Caution => "Weak signals detected. Check the sender before continuing.",
                Verdict.Safe => "No phishing indicators were detected.",
                _ => ErrorMessage ?? "The input could not be analysed."
            };
        }
    }

    /// <summary>Set when the input could not be parsed.</summary>
    public string? ErrorMessage { get; init; }

    /// <summary>True when the scan produced a usable verdict.</summary>
    public bool IsValid => Verdict != Verdict.Unknown;

    /// <summary>True when the user should not open the link.</summary>
    public bool ShouldWarn => Verdict is Verdict.Suspicious or Verdict.Malicious;

    /// <summary>Creates an error result for input that could not be parsed.</summary>
    /// <param name="input">Original input.</param>
    /// <param name="message">Reason the input was rejected.</param>
    public static ScanResult Failure(string input, string message) => new()
    {
        Input = input,
        Verdict = Verdict.Unknown,
        Score = 0,
        Findings = Array.Empty<RiskFinding>(),
        ScannedAt = DateTimeOffset.UtcNow,
        ErrorMessage = message
    };
}