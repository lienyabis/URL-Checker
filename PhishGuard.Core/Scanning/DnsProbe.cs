using System.Net;
using PhishGuard.Core.Models;

namespace PhishGuard.Core.Scanning;

/// <summary>
/// Optional network probe that resolves a host name.
/// Only runs when the caller explicitly enables <see cref="ScanOptions.ResolveDns"/>.
/// </summary>
public static class DnsProbe
{
    /// <summary>
    /// Resolves <paramref name="host"/> and appends a finding describing the outcome.
    /// Network failures are reported as informational rather than risky, because
    /// an unreachable host usually means "offline", not "malicious".
    /// </summary>
    /// <param name="host">Host name to resolve.</param>
    /// <param name="findings">Sink for the resulting finding.</param>
    public static void AppendDnsFinding(string host, List<RiskFinding> findings)
    {
        try
        {
            var addresses = Dns.GetHostAddressesAsync(host).GetAwaiter().GetResult();

            if (addresses.Length == 0)
            {
                findings.Add(new RiskFinding(
                    "DNS_NO_RECORDS",
                    "Host name does not resolve",
                    $"No DNS records were found for '{host}'. Domains used for " +
                    "phishing often have very short lifetimes.",
                    Severity.Low));

                return;
            }

            var first = addresses[0];
            findings.Add(new RiskFinding(
                "DNS_RESOLVED",
                "Host resolved",
                $"'{host}' resolves to {string.Join(", ", addresses.Take(3))}.",
                Severity.Info));
        }
        catch (Exception ex) when (ex is System.Net.Sockets.SocketException or ArgumentException)
        {
            findings.Add(new RiskFinding(
                "DNS_LOOKUP_FAILED",
                "DNS lookup failed",
                $"Could not resolve '{host}': {ex.Message}",
                Severity.Info));
        }
    }
}