namespace PhishGuard.Core.Models;

/// <summary>
/// Overall safety classification produced by a scan.
/// </summary>
public enum Verdict
{
    /// <summary>The input could not be interpreted as a URL at all.</summary>
    Unknown = 0,

    /// <summary>No meaningful risk indicators were found.</summary>
    Safe = 1,

    /// <summary>A few weak signals, or an unverifiable host. Worth a second look.</summary>
    Caution = 2,

    /// <summary>Multiple strong phishing indicators. Do not enter credentials.</summary>
    Suspicious = 3,

    /// <summary>Confirmed match against a known-bad list, or a decisive malicious pattern.</summary>
    Malicious = 4
}

/// <summary>
/// Helpers for rendering <see cref="Verdict"/> values.
/// </summary>
public static class VerdictExtensions
{
    /// <summary>Human readable label for a verdict.</summary>
    public static string ToLabel(this Verdict verdict) => verdict switch
    {
        Verdict.Safe => "SAFE",
        Verdict.Caution => "CAUTION",
        Verdict.Suspicious => "SUSPICIOUS",
        Verdict.Malicious => "MALICIOUS",
        _ => "UNKNOWN"
    };

    /// <summary>One-line advice shown to the user for a verdict.</summary>
    public static string ToAdvice(this Verdict verdict) => verdict switch
    {
        Verdict.Safe => "No phishing indicators detected. Stay alert anyway.",
        Verdict.Caution => "Some weak signals detected. Verify the sender before proceeding.",
        Verdict.Suspicious => "Strong phishing indicators. Do not sign in or enter any data.",
        Verdict.Malicious => "Confirmed malicious link. Do not open it.",
        _ => "The input could not be analysed as a URL."
    };

    /// <summary>Colour used by the UI for this verdict (ARGB).</summary>
    public static uint ToArgb(this Verdict verdict) => verdict switch
    {
        Verdict.Safe => 0xFF107C41,        // green
        Verdict.Caution => 0xFFB26A00,     // amber
        Verdict.Suspicious => 0xFFC4314B,   // red
        Verdict.Malicious => 0xFF8B0000,   // dark red
        _ => 0xFF5A5A5A                   // grey
    };
}