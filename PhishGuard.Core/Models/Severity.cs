namespace PhishGuard.Core.Models;

/// <summary>
/// How much a single <see cref="RiskFinding"/> contributes to the overall risk score.
/// </summary>
public enum Severity
{
    /// <summary>Purely informational; adds no points.</summary>
    Info = 0,

    /// <summary>Weak signal on its own; ambiguous but worth noting.</summary>
    Low = 1,

    /// <summary>Recognised phishing pattern.</summary>
    Medium = 2,

    /// <summary>Strong indicator that is rarely seen on legitimate sites.</summary>
    High = 3,

    /// <summary>Decisive on its own; sufficient to condemn the URL.</summary>
    Critical = 4
}

/// <summary>
/// Extensions for <see cref="Severity"/>.
/// </summary>
public static class SeverityExtensions
{
    /// <summary>Points added to the risk score for this severity.</summary>
    public static int ToPoints(this Severity severity) => severity switch
    {
        Severity.Info => 0,
        Severity.Low => 8,
        Severity.Medium => 20,
        Severity.High => 32,
        Severity.Critical => 55,
        _ => 0
    };

    /// <summary>Short tag rendered in the findings table.</summary>
    public static string ToTag(this Severity severity) => severity switch
    {
        Severity.Info => "INFO",
        Severity.Low => "LOW",
        Severity.Medium => "MED",
        Severity.High => "HIGH",
        Severity.Critical => "CRIT",
        _ => "INFO"
    };
}