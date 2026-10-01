namespace PhishGuard.Core.Models;

/// <summary>
/// A single risk signal produced by one of the analysers.
/// </summary>
/// <param name="Code">Stable machine readable identifier, e.g. <c>IP_LITERAL_HOST</c>.</param>
/// <param name="Title">Short headline shown in the UI.</param>
/// <param name="Detail">Explanation of why this matters.</param>
/// <param name="Severity">How much this signal contributes to the score.</param>
public sealed record RiskFinding(
    string Code,
    string Title,
    string Detail,
    Severity Severity);