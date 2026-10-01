namespace PhishGuard.Core.Data;

/// <summary>
/// Keyword groups that strongly correlate with credential-harvesting pages.
/// Each group is a set of words that usually appear together in phishing URLs.
/// </summary>
public static class SuspiciousKeywords
{
    /// <summary>
    /// Credential-capture wording. Seeing one of these in the host is a mild signal;
    /// seeing one in the host of a non-brand domain is a strong signal.
    /// </summary>
    public static readonly string[] AuthKeywords =
    {
        "login", "signin", "log-in", "sign-in", "logon", "auth", "authenticate",
        "account", "accounts", "verify", "verification", "validate", "confirm",
        "secure", "security", "update-info", "recover", "recovery", "unlock",
        "password", "passwd", "credential", "credentials", "session", "webmail"
    };

    /// <summary>
    /// Urgency and threat language used to pressure victims into acting quickly.
    /// </summary>
    public static readonly string[] UrgencyKeywords =
    {
        "suspend", "suspended", "urgent", "alert", "warning", "expired", "expiry",
        "locked", "deactivated", "disabled", "limited", "unusual", "unauthorized",
        "unauthorised", "billing", "payment", "refund", "invoice", "charge",
        "failed", "pending", "hold", "action-required", "required", "final-notice"
    };

    /// <summary>
    /// Reward bait: prize, refund, gift-card scams.
    /// </summary>
    public static readonly string[] RewardKeywords =
    {
        "prize", "winner", "reward", "bonus", "gift", "giveaway", "promo",
        "voucher", "coupon", "discount", "free", "bonus", "lottery", "jackpot",
        "claim", "airdrop", "giveback", "cashback", "offer", "deal", "sale"
    };

    /// <summary>
    /// Deliverable asset theft, common in crypto and gift-card scams.
    /// </summary>
    public static readonly string[] TheftKeywords =
    {
        "wallet", "seed", "mnemonic", "privatekey", "private-key", "keystore",
        "2fa", "otp", "one-time", "onetime", "pin", "card", "creditcard", "cvv",
        "ssn", "social-security", "passport", "licence", "license", "id-card",
        "kyc", "iban", "swift", "routing", "sort-code", "sortcode"
    };

    /// <summary>All keyword groups combined.</summary>
    public static IReadOnlyList<string> All { get; } =
        AuthKeywords
        .Concat(UrgencyKeywords)
        .Concat(RewardKeywords)
        .Concat(TheftKeywords)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();
}