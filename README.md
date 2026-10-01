# PhishGuard — URL Safety Checker

A Windows desktop application, written in **C#**, that checks whether a link is
safe **before** you open it. It identifies phishing pages, scam sites, credential
harvesting forms, brand-impersonation domains and other malicious infrastructure.

Paste a URL, press **Check URL**, and PhishGuard returns a verdict
(`SAFE` / `CAUTION` / `SUSPICIOUS` / `MALICIOUS`), a risk score out of 100, and a
plain-English explanation of every risk indicator it detected.

---

## Table of contents

1. [What it does](#1-what-it-does)
2. [How detection works](#2-how-detection-works)
3. [Verdict levels](#3-verdict-levels)
4. [Project structure](#4-project-structure)
5. [Requirements](#5-requirements)
6. [Building and running](#6-building-and-running)
7. [Running the tests](#7-running-the-tests)
8. [Using the application](#8-using-the-application)
9. [API reference](#9-api-reference)
10. [Extending PhishGuard](#10-extending-phishguard)
11. [Limitations and responsible use](#11-limitations-and-responsible-use)

---

## 1. What it does

PhishGuard answers one question: **"Is this link safe to open?"**

It combines two complementary approaches, because neither works well alone:

| Approach | Catches | Misses |
|---|---|---|
| **Known-bad list** (blocklist) | Domains *already confirmed* malicious | Brand-new phishing domains seen for the first time |
| **Heuristics** (structural analysis) | *Unseen* phishing domains, by recognising attacker patterns | Domains that look perfectly ordinary |

The heuristics are what make the tool useful against fresh campaigns, where a
blocklist entry cannot possibly exist yet.

### Supported inputs

* Full URLs — `https://example.com/login`
* Bare hosts — `example.com/login` (HTTPS is assumed)
* Defanged links as found in reports — `hxxps://evil[.]com` (automatically refanged)
* Unicode/IDN domains — `https://xn--80ak6aa92e.com`
* URLs containing embedded credentials — `https://paypal.com@evil.tk`
* IPv4/IPv6 literals — `http://192.168.1.1/login`

---

## 2. How detection works

When you press **Check URL**, the input passes through a pipeline. Each stage is
an independent, testable class.

### Stage 1 — Normalisation (`UrlNormalizer`)

Real-world links are messy. Before any analysis, PhishGuard cleans the input:

* Strips surrounding quotes, angle brackets and whitespace
* Removes zero-width characters (`U+200B`–`U+200D`, `U+FEFF`) used to break up keywords
* Refangs defanged text: `hxxp` → `http`, `[.]` → `.`, `[:]` → `:`
* Adds a scheme when one is missing
* Lower-cases the host and strips a trailing dot (`example.com.` → `example.com`)
* Decodes punycode (`xn--…`) into Unicode so brand checks work on real text

Non-web schemes (`javascript:`, `data:`, `file:`, `vbscript:`, `blob:`) are
**rejected outright**, since they can never represent a normal web page.

### Stage 2 — Analysis

Five analysers run in order. Each contributes findings independently.

#### 1. `BlocklistAnalyzer` — known-bad matching

Checks the host against the blocklist. Supports exact domains and `*.` wildcards
that match any subdomain or deeper nesting.

A match is **decisive**: the verdict becomes `MALICIOUS` regardless of score.

#### 2. `BrandImpersonationAnalyzer` — brand spoofing

The most valuable heuristic. It knows the **real** domains of ~75 brands (PayPal,
Microsoft, Apple, Amazon, banks, crypto wallets, antivirus vendors…).

If the host mentions a brand but is **not** on that brand's official domain, it is
flagged. It catches two patterns:

* **Substring** — `paypal-secure.tk`, `micros0ft-support.top`
* **Typosquatting** — a label within a small edit distance of a brand token
  (`paypa1`, `g00gle`), using **Levenshtein distance**

#### 3. `HomographAnalyzer` — unicode deception

Detects domains engineered to *look* identical to a real one:

* **Punycode hosts** (`xn--…`) — `xn--80ak6aa92e.com`
* **Mixed-script labels** — `аррӏе.com` mixes Cyrillic `а`, `р`, `ӏ` with Latin `e`

Confusable characters (Cyrillic/Greek/full-width forms) are first mapped to their
ASCII equivalents, so `раураl` collapses to `paypal` before brand matching.

#### 4. `StructuralAnalyzer` — URL shape

Feed-independent checks on the shape of the URL:

| Code | Meaning |
|---|---|
| `IP_LITERAL_HOST` | Bare IP address instead of a domain name (worse if private/loopback) |
| `EMBEDDED_REGISTRABLE_DOMAIN` | A whole domain hidden mid-host: `paypal.com.evil.tk` |
| `DEEP_SUBDOMAIN` | Five or more host labels, used to push the real domain out of view |
| `NOISY_LABEL` | Label padded with ≥3 hyphens or ≥3 digits — machine-generated |
| `LONG_HOST` | Host longer than 50 characters |
| `EMBEDDED_CREDENTIALS` | `https://paypal.com@evil.tk` — the `user@` trick |
| `UNUSUAL_PORT` | Port 8080, 8000, 3000, 5000, 8443, 81, 8888 |
| `NO_TLS` | Plain `http://` instead of `https://` |
| `OBFUSCATED_PATH` | Five or more percent-escapes hiding the real target |
| `DEEP_PATH` | Path nested six or more levels |

`EMBEDDED_REGISTRABLE_DOMAIN` deserves emphasis: in `paypal.com.evil.tk` the eye
reads "paypal.com" first, but the site is actually served from `evil.tk`.
#### 5. `KeywordAnalyzer` - phishing vocabulary and TLDs

Looks for four keyword groups in the host:

* **Auth** - `login`, `verify`, `secure`, `account`, `password`, `recover` (medium)
* **Urgency** - `suspended`, `expired`, `unusual`, `billing`, `refund` (low)
* **Reward** - `prize`, `winner`, `giftcard`, `airdrop`, `claim` (low)
* **Asset theft** - `wallet`, `seed`, `mnemonic`, `otp`, `cvv`, `iban` (medium)

It also flags **high-abuse TLDs** such as `.tk`, `.ml`, `.ga`, `.cf`, `.gq`,
`.zip`, `.mov`, `.click` - cheap, lightly moderated, and disproportionately used
for disposable phishing infrastructure.

> **Important:** keyword analysis is deliberately **suppressed on genuine brand
> domains**. `login.microsoftonline.com` contains "login" and is perfectly safe;
> `login-evil.tk` contains "login" and is not. Without this rule the tool would
> be unusable.

### Stage 3 - Scoring

Each finding carries a `Severity`, which converts to points:

| Severity | Points |
|---|---|
| `Info` | 0 |
| `Low` | 8 |
| `Medium` | 20 |
| `High` | 32 |
| `Critical` | 55 |

Repeated signals of the *same kind* are damped (`points / (1 + count)`), so one
noisy URL cannot reach 100 merely by triggering many related rules. The final
score is clamped to **0-100**.

The verdict is then decided:

* Any `Critical` finding -> **MALICIOUS**
* Any `High` finding -> **SUSPICIOUS**
* Score >= 30 -> **SUSPICIOUS**
* Score >= 10 -> **CAUTION**
* Otherwise -> **SAFE**

---

## 3. Verdict levels

| Verdict | Colour | Meaning | What to do |
|---|---|---|---|
| **SAFE** | Green | No phishing indicators found | Proceed, but stay alert |
| **CAUTION** | Amber | Weak signals only | Verify the sender before proceeding |
| **SUSPICIOUS** | Red | Strong phishing indicators | **Do not** sign in or enter data |
| **MALICIOUS** | Dark red | Confirmed malicious, or decisive pattern | **Do not open it** |

A verdict of `SAFE` means *"no indicators were found"* - **not** *"this site is
guaranteed legitimate"*. See [Limitations](#11-limitations-and-responsible-use).

### Worked examples

| URL | Verdict | Why |
|---|---|---|
| `https://github.com/microsoft/vscode` | SAFE | No indicators |
| `https://paypal.com/signin` | SAFE | Real PayPal domain; brand keywords suppressed |
| `http://paypal-secure.tk/login` | MALICIOUS | Brand impersonation + auth keyword + no TLS + risky TLD |
| `https://webscr-paypal-secure.tk/` | MALICIOUS | Blocklist hit |
| `http://192.168.1.50/login.php` | MALICIOUS | Private IP literal host |
| `https://xn--80ak6aa92e.com/` | MALICIOUS | Punycode host |
| `http://paypal.com.secure-update.tk/` | MALICIOUS | Real domain hidden mid-host |
| `javascript:alert(1)` | UNKNOWN | Rejected - not a web URL |

---

## 4. Project structure

```
PhishGuard/
|-- PhishGuard.sln                  # Solution file
|-- README.md                       # This documentation
|
|-- PhishGuard.Core/                # Detection engine (no UI, fully testable)
|   |-- Models/
|   |   |-- Verdict.cs              # Verdict enum + labels, advice, colours
|   |   |-- Severity.cs             # Severity enum + point values
|   |   |-- RiskFinding.cs          # A single risk signal
|   |   |-- ScanResult.cs           # Full result of one scan
|   |   `-- ScanOptions.cs          # Optional network probes
|   |-- Parsing/
|   |   `-- UrlNormalizer.cs        # Messy input -> canonical Uri
|   |-- Data/
|   |   |-- BrandRegistry.cs        # ~75 brands + real domains
|   |   |-- PhishingBlocklist.cs    # Known-bad list, file loading
|   |   |-- RiskyTlds.cs            # High-abuse TLDs
|   |   `-- SuspiciousKeywords.cs   # Phishing vocabulary groups
|   |-- Text/
|   |   `-- TextAnalysis.cs         # Levenshtein, confusables, scripts
|   |-- Analysis/
|   |   |-- IUrlAnalyzer.cs         # Analyser interface + context
|   |   |-- BlocklistAnalyzer.cs
|   |   |-- BrandImpersonationAnalyzer.cs
|   |   |-- HomographAnalyzer.cs
|   |   |-- StructuralAnalyzer.cs
|   |   `-- KeywordAnalyzer.cs
|   `-- Scanning/
|       |-- UrlScanner.cs           # Orchestrator + scoring
|       `-- DnsProbe.cs             # Optional DNS resolution
|
|-- PhishGuard.App/                 # Windows Forms desktop UI
|   |-- Program.cs                  # Entry point
|   |-- MainForm.cs                 # Main window
|   `-- UiFactory.cs                # Control helpers + RiskMeter
|
|-- PhishGuard.Tests/               # Detection test suite (91 assertions)
|   |-- Program.cs
|   |-- TestRunner.cs
|   `-- HelperTests.cs
|
`-- PhishGuard.UiSmokeTest/         # Renders the UI to PNG for verification
    `-- Program.cs
```

### Design decisions

* **Separation of concerns.** `PhishGuard.Core` has zero UI dependencies, so the
  detection logic is testable in isolation and could be reused in a CLI, browser
  extension or web service.
* **No UI designer files.** The form is built in code. Designer files and
  `.resx` resources are fragile to merge and offer no benefit for a single form.
* **No NuGet dependencies.** Only the .NET base class library is used, so the
  project builds offline and has no supply-chain surface.
* **Offline by default.** A scan makes **no network requests** unless the caller
  explicitly opts in via `ScanOptions`.

---

## 5. Requirements

| Component | Version |
|---|---|
| OS | Windows 10 (1809+) or Windows 11 |
| .NET SDK | **8.0** or later (to build) |
| .NET Desktop Runtime | **8.0** or later (to run the GUI) |

The GUI requires the **Desktop Runtime**, which is separate from the plain .NET
runtime. If you see *"You must install .NET Desktop Runtime"*, install it from
<https://dotnet.microsoft.com/download/dotnet/8.0>.

---

## 6. Building and running

From the `PhishGuard` folder:

```bash
# Restore and build everything
dotnet build PhishGuard.sln

# Run the desktop application
dotnet run --project PhishGuard.App
```

The compiled executable is produced at:

```
PhishGuard.App\bin\Debug\net8.0-windows\PhishGuard.exe
```

### Publishing a self-contained build

To produce a folder that runs on machines without .NET installed:

```bash
dotnet publish PhishGuard.App -c Release -r win-x64 --self-contained true
```

### If the app reports a missing .NET Desktop Runtime

The GUI needs the *Desktop* runtime, which is separate from the base runtime. If
your .NET installation is user-scoped rather than machine-wide, point the
launcher at it explicitly:

```powershell
$env:DOTNET_ROOT = "$env:LOCALAPPDATA\Microsoft\dotnet"
.\PhishGuard.exe
```

---

## 7. Running the tests

The test suite has **no external dependencies** - it is a plain console runner,
so it works offline and needs no test-framework packages.

```bash
dotnet run --project PhishGuard.Tests
```

Expected output:

```
PhishGuard detection test suite
========================================================================
-- must be flagged MALICIOUS --
-- must be flagged, at least suspicious --
-- legitimate sites must not be flagged --
-- malformed input --
-- normalisation --
-- helper functions --
-- labels and scoring helpers --

========================================================================
Passed: 91   Failed: 0
All tests passed.
```

The process returns exit code `0` on success and `1` on failure, so it can be
wired into CI.

### Coverage

| Group | What it verifies |
|---|---|
| Malicious URLs | Brand spoofing, IP hosts, blocklist hits, deep subdomains, punycode all reach `MALICIOUS` with the expected finding code |
| Legitimate URLs | Google, GitHub, PayPal, Microsoft, Wikipedia, Amazon, Stack Overflow and others are **not** flagged |
| Malformed input | Empty, whitespace, `javascript:`, `data:`, `file:` and non-URL text are rejected |
| Normalisation | Missing scheme, mixed case, whitespace and defanged links resolve to the correct host |
| Helpers | Levenshtein distance (including symmetry), blocklist wildcard/hosts-file parsing, IDN decoding |
| Scoring | Clean URLs score 0, scores stay within 0-100, findings are sorted by severity |

### UI smoke test

`PhishGuard.UiSmokeTest` renders the real window to PNG files, which is how the
interface was verified during development:

```bash
dotnet run --project PhishGuard.UiSmokeTest -- ./renders
```

It exercises the idle, phishing, blocklisted, raw-IP, legitimate and invalid
states and prints the resulting verdict for each.

---

## 8. Using the application

1. **Launch** PhishGuard.
2. **Paste** a URL (or type one) into the input box and press **Check URL**.
3. **Read the verdict** at the top of the panel.
4. **Review the indicators** - every detected risk is listed with a plain-English
   explanation. Double-click any row for full detail.
5. Only press **Open link** once you are satisfied the site is legitimate.

### Keyboard shortcuts

| Key | Action |
|---|---|
| `Enter` | Run the scan |
| `Enter` on a selected row | Show full detail for that indicator |

### Notes

* Scans run **entirely offline** - nothing about the URL is sent anywhere.
* **Open link** asks for confirmation, with a stronger warning for links that
  were flagged as dangerous.
* The status bar shows which host was scanned and when.

---

## 9. API reference

The engine is usable without the UI.

```csharp
using PhishGuard.Core.Models;
using PhishGuard.Core.Scanning;

var scanner = new UrlScanner();

ScanResult result = scanner.Scan("http://paypal-secure.tk/login");

Console.WriteLine(result.Verdict);      // Malicious
Console.WriteLine(result.Verdict.ToLabel());  // "MALICIOUS"
Console.WriteLine(result.Score);        // 100
Console.WriteLine(result.Summary);

foreach (RiskFinding finding in result.Findings)
{
    Console.WriteLine($"{finding.Severity.ToTag(),-5} {finding.Code,-28} {finding.Title}");
}
```

### Scanning many URLs

```csharp
IReadOnlyList<ScanResult> results = scanner.ScanMany(urls);
```

### Using a real blocklist feed

```csharp
var blocklist = new PhishingBlocklist(includeBuiltInSeed: false);
blocklist.LoadFromFile(@"C:\feeds\phishing-domains.txt");

var scanner = new UrlScanner(blocklist, UrlScanner.DefaultAnalyzers());
```

The loader understands newline-delimited hosts-file format, plain domains,
`*.` wildcards, `#` / `!` comments, and full URLs (reduced to their host).

### Enabling the optional DNS probe

DNS resolution is **off** by default. Opt in explicitly:

```csharp
var result = scanner.Scan("https://suspicious.example", new ScanOptions
{
    ResolveDns = true
});
```

### Adding your own analyser

Implement `IUrlAnalyzer` and pass it to the scanner:

```csharp
public sealed class ShortenerAnalyzer : IUrlAnalyzer
{
    public string Name => "Shortener";

    public void Analyze(ParsedUrl url, AnalysisContext context, List<RiskFinding> findings)
    {
        if (url.Host.EndsWith("bit.ly", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new RiskFinding(
                "URL_SHORTENER",
                "Link shortener hides the real destination",
                "The true target cannot be seen until the link is opened.",
                Severity.Medium));
        }
    }
}

var scanner = new UrlScanner(
    new PhishingBlocklist(),
    UrlScanner.DefaultAnalyzers().Append(new ShortenerAnalyzer()));
```

---

## 10. Extending PhishGuard

### Add a brand

Edit the `All` array in `PhishGuard.Core/Data/BrandRegistry.cs`:

```csharp
new("Acme Bank", new[] { "acmebank.com", "acme.co.uk" }),
```

Listing the *real* domains is what prevents false positives, so be accurate here.

### Add suspicious keywords

Edit the relevant array in `PhishGuard.Core/Data/SuspiciousKeywords.cs`.

### Add a high-abuse TLD

Add it to `Free`, `Disposables` or `BrandAbuse` in
`PhishGuard.Core/Data/RiskyTlds.cs`.

### Tune scoring

* Point values: `SeverityExtensions.ToPoints` in `Models/Severity.cs`
* Verdict thresholds: `UrlScanner.ScoreVerdict` in `Scanning/UrlScanner.cs`

---

## 11. Limitations and responsible use

Please read this section before relying on PhishGuard for anything important.

### What this tool does **not** do

* **It is not a virus scanner.** It analyses the *link*, not the page content.
* **It does not visit the URL by default.** A clean-looking domain may still
  serve a malicious page after a redirect.
* **It does not inspect the page.** Phishing logic hidden entirely in the page
  body is not detected.
* **It cannot detect an unknown threat with no visible signal.** A carefully
  built phishing site on `https://acme-bank-login.com` registered through a
  reputable registrar, using a `.com` domain and no brand typos, may well be
  reported SAFE.
* **A SAFE verdict is not a guarantee.** It means *"no known indicator was
  found"* - nothing more.

### False negatives and false positives

No heuristic is perfect. Expect occasional false positives (harmless URLs
flagged) and false negatives (malicious URLs passed). The weights are tuned to
favour **false positives**, on the assumption that a false alarm is far cheaper
than a compromised account.

### Privacy

Scans run locally and make no network requests. If you enable the DNS probe, only
a hostname lookup is performed - the URL path is never transmitted, and the
target server is never contacted.

### Responsible use

* Do **not** use this to block or interfere with sites you do not own.
* Phishing URLs are dangerous to click. If you must investigate one, do it in an
  isolated, disposable environment - never on a machine holding real credentials.
* Report confirmed phishing to the appropriate authority for your region, such as
  the brand being impersonated, your national CERT, or the hosting provider.
* Keep the blocklist current; a stale list protects nothing on its own.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| *"You must install .NET Desktop Runtime"* | Install the .NET **Desktop** Runtime 8.0+ |
| App starts but the window is blank | Ensure `net8.0-windows` is targeting correctly and rebuild |
| `dotnet` not recognised | Install the .NET SDK and reopen the terminal |
| All verdicts are SAFE | The blocklist is a small built-in seed; load a real feed (see section 9) |

---

## Licence

Provided for educational and defensive-security purposes. You are responsible
for how you use it.
