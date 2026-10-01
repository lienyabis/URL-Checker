namespace PhishGuard.Core.Data;

/// <summary>
/// A brand that is commonly impersonated by phishing campaigns.
/// </summary>
/// <param name="Name">Display name of the brand.</param>
/// <param name="LegitimateDomains">
/// Domains that genuinely belong to the brand. A URL on one of these is never
/// penalised for mentioning the brand name.
/// </param>
public sealed record Brand(string Name, string[] LegitimateDomains);

/// <summary>
/// Built-in list of frequently impersonated brands and their real domains.
/// Used to detect "paypa1-secure.tk" style look-alike hosts.
/// </summary>
public static class BrandRegistry
{
    private static readonly Brand[] All =
    {
        new("PayPal", new[] { "paypal.com", "paypal.me", "paypalobjects.com" }),
        new("Microsoft", new[] { "microsoft.com", "microsoftonline.com", "live.com", "msn.com", "outlook.com", "office.com", "office365.com", "azure.com", "windows.com", "bing.com", "linkedin.com" }),
        new("Apple", new[] { "apple.com", "icloud.com", "itunes.com" }),
        new("Amazon", new[] { "amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp", "aws.amazon.com", "amzn.to" }),
        new("Google", new[] { "google.com", "gmail.com", "youtube.com", "goo.gl", "google.co.uk", "googleapis.com", "withgoogle.com" }),
        new("Facebook", new[] { "facebook.com", "fb.com", "fbcdn.net", "messenger.com", "meta.com" }),
        new("Instagram", new[] { "instagram.com", "cdninstagram.com" }),
        new("WhatsApp", new[] { "whatsapp.com", "wa.me" }),
        new("LinkedIn", new[] { "linkedin.com", "lnkd.in" }),
        new("Netflix", new[] { "netflix.com", "nflximg.net", "nflxvideo.net" }),
        new("Twitter/X", new[] { "twitter.com", "x.com", "t.co" }),
        new("TikTok", new[] { "tiktok.com", "tiktokv.com" }),
        new("Snapchat", new[] { "snapchat.com" }),
        new("Dropbox", new[] { "dropbox.com", "dropboxusercontent.com" }),
        new("Docusign", new[] { "docusign.com", "docusign.net" }),
        new("Adobe", new[] { "adobe.com", "acrobat.adobe.com" }),
        new("Steam", new[] { "steampowered.com", "steamcommunity.com", "valvesoftware.com" }),
        new("Discord", new[] { "discord.com", "discord.gg", "discordapp.com" }),
        new("Coinbase", new[] { "coinbase.com" }),
        new("Binance", new[] { "binance.com", "binance.us" }),
        new("MetaMask", new[] { "metamask.io" }),
        new("Ledger", new[] { "ledger.com" }),
        new("Chase", new[] { "chase.com", "jpmorganchase.com" }),
        new("Bank of America", new[] { "bankofamerica.com", "bofa.com" }),
        new("Wells Fargo", new[] { "wellsfargo.com" }),
        new("Citibank", new[] { "citi.com", "citibank.com" }),
        new("HSBC", new[] { "hsbc.com", "hsbc.co.uk" }),
        new("Barclays", new[] { "barclays.co.uk", "barclays.com" }),
        new("Lloyds Bank", new[] { "lloydsbank.com" }),
        new("Santander", new[] { "santander.co.uk", "santander.com" }),
        new("Deutsche Bank", new[] { "db.com", "deutsche-bank.de" }),
        new("BNP Paribas", new[] { "bnpparibas.com" }),
        new("Credit Agricole", new[] { "credit-agricole.fr" }),
        new("UBS", new[] { "ubs.com" }),
        new("Revolut", new[] { "revolut.com" }),
        new("Wise", new[] { "wise.com", "transferwise.com" }),
        new("Payoneer", new[] { "payoneer.com" }),
        new("Western Union", new[] { "westernunion.com" }),
        new("MoneyGram", new[] { "moneygram.com" }),
        new("Venmo", new[] { "venmo.com" }),
        new("CashApp", new[] { "cash.app" }),
        new("Zelle", new[] { "zellepay.com", "zelle.com" }),
        new("IRS", new[] { "irs.gov" }),
        new("HMRC", new[] { "hmrc.gov.uk" }),
        new("USPS", new[] { "usps.com", "usps.gov" }),
        new("UPS", new[] { "ups.com" }),
        new("Geek Squad", new[] { "geeksquad.com", "bestbuy.com" }),
        new("McAfee", new[] { "mcafee.com" }),
        new("Norton", new[] { "norton.com" }),
        new("Avast", new[] { "avast.com" }),
        new("Kaspersky", new[] { "kaspersky.com" }),
        new("Bitdefender", new[] { "bitdefender.com" }),
        new("Malwarebytes", new[] { "malwarebytes.com" }),
        new("eBay", new[] { "ebay.com", "ebay.co.uk", "ebayimg.com" }),
        new("Etsy", new[] { "etsy.com" }),
        new("Walmart", new[] { "walmart.com" }),
        new("Target", new[] { "target.com" }),
        new("Best Buy", new[] { "bestbuy.com" }),
        new("Costco", new[] { "costco.com" }),
        new("Alibaba", new[] { "alibaba.com", "aliexpress.com" }),
        new("Temu", new[] { "temu.com" }),
        new("Shein", new[] { "shein.com" }),
        new("Spotify", new[] { "spotify.com" }),
        new("Roblox", new[] { "roblox.com" }),
        new("Epic Games", new[] { "epicgames.com" }),
        new("Activision", new[] { "activision.com" }),
        new("Zoom", new[] { "zoom.us" }),
        new("Slack", new[] { "slack.com" }),
        new("Notion", new[] { "notion.so" }),
        new("Figma", new[] { "figma.com" }),
        new("GitHub", new[] { "github.com", "githubusercontent.com" }),
        new("GitLab", new[] { "gitlab.com" }),
        new("Cloudflare", new[] { "cloudflare.com" }),
        new("Namecheap", new[] { "namecheap.com" }),
        new("GoDaddy", new[] { "godaddy.com" }),
        new("Xfinity", new[] { "xfinity.com" }),
        new("Comcast", new[] { "comcast.net" })
    };

    /// <summary>All known brands.</summary>
    public static IReadOnlyList<Brand> Brands { get; } = All;

    /// <summary>
    /// Lower-cased tokens derived from brand names, used for fuzzy look-alike matching.
    /// </summary>
    public static IReadOnlyList<string> BrandTokens { get; } =
        All.SelectMany(b => Tokenize(b.Name))
           .Distinct(StringComparer.OrdinalIgnoreCase)
           .ToArray();

    /// <summary>
    /// Returns true when <paramref name="host"/> is the brand's domain or a subdomain of it.
    /// </summary>
    public static bool IsLegitimateDomain(string host, Brand brand) =>
        brand.LegitimateDomains.Any(d =>
            host.Equals(d, StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith("." + d, StringComparison.OrdinalIgnoreCase));

    /// <summary>
    /// Returns the brand whose legitimate domain matches the host exactly, if any.
    /// </summary>
    public static Brand? FindOwningBrand(string host) =>
        Brands.FirstOrDefault(b => IsLegitimateDomain(host, b));

    private static IEnumerable<string> Tokenize(string brandName)
    {
        // "Bank of America" -> ["bankofamerica", "bank", "america"]
        var compact = new string(brandName.Where(char.IsLetterOrDigit).ToArray())
            .ToLowerInvariant();

        if (compact.Length > 3)
        {
            yield return compact;
        }

        foreach (var word in brandName.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            var token = new string(word.Where(char.IsLetterOrDigit).ToArray()).ToLowerInvariant();
            if (token.Length > 3)
            {
                yield return token;
            }
        }
    }
}