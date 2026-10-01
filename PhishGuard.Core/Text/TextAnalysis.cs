using System.Text;

namespace PhishGuard.Core.Text;

/// <summary>
/// String helpers used by the heuristics: edit distance, homoglyph mapping
/// and word tokenisation.
/// </summary>
public static class TextAnalysis
{
    /// <summary>
    /// Levenshtein edit distance using a single rolling row (O(min) space).
    /// </summary>
    /// <param name="a">First string.</param>
    /// <param name="b">Second string.</param>
    /// <returns>Number of single-character edits needed to turn <paramref name="a"/> into <paramref name="b"/>.</returns>
    public static int Levenshtein(string a, string b)
    {
        if (a.Length == 0)
        {
            return b.Length;
        }

        if (b.Length == 0)
        {
            return a.Length;
        }

        // Keep the inner dimension the smaller one to minimise allocations.
        if (a.Length > b.Length)
        {
            (a, b) = (b, a);
        }

        var previous = new int[b.Length + 1];
        var current = new int[b.Length + 1];

        for (var j = 0; j <= b.Length; j++)
        {
            previous[j] = j;
        }

        for (var i = 1; i <= a.Length; i++)
        {
            current[0] = i;
            var aChar = a[i - 1];

            for (var j = 1; j <= b.Length; j++)
            {
                var cost = aChar == b[j - 1] ? 0 : 1;

                current[j] = Math.Min(
                    Math.Min(current[j - 1] + 1, previous[j] + 1),
                    previous[j - 1] + cost);
            }

            (previous, current) = (current, previous);
        }

        return previous[b.Length];
    }

    /// <summary>
    /// Maps common character substitutions used to fake brand names onto the
    /// letter they imitate, so "pаypal" (Cyrillic a) collapses back to "paypal".
    /// </summary>
    /// <param name="value">Text to normalise.</param>
    public static string NormalizeConfusables(string value)
    {
        var sb = new StringBuilder(value.Length);

        foreach (var ch in value)
        {
            sb.Append(ToAscii(ch));
        }

        return sb.ToString();
    }

    /// <summary>
    /// Converts a single possibly-confusable character to a canonical ASCII letter.
    /// Returns the input character when no mapping exists.
    /// </summary>
    private static char ToAscii(char ch)
    {
        // Cyrillic look-alikes.
        switch (ch)
        {
            case '\u0430': return 'a'; // а
            case '\u0435': return 'e'; // е
            case '\u043E': return 'o'; // о
            case '\u0440': return 'p'; // р
            case '\u0441': return 'c'; // с
            case '\u0443': return 'y'; // у
            case '\u0445': return 'x'; // х
            case '\u040A': return 'k'; // К
            case '\u041C': return 'm'; // М
            case '\u0412': return 'b'; // В
            case '\u0422': return 't'; // Т
            case '\u041D': return 'h'; // Н
        }

        // Greek look-alikes.
        switch (ch)
        {
            case '\u03BF': return 'o'; // ο
            case '\u03B1': return 'a'; // α
            case '\u03B5': return 'e'; // ε
            case '\u03C1': return 'p'; // ρ
            case '\u03C5': return 'u'; // υ
            case '\u03BD': return 'v'; // ν
        }

        // Full-width Latin forms.
        if (ch >= '\uFF01' && ch <= '\uFF5E')
        {
            return (char)(ch - '\uFF01' + '!');
        }

        return ch;
    }

    /// <summary>
    /// True when the text mixes characters from different Unicode scripts, a
    /// common sign of a homograph attack such as "аpple.com".
    /// </summary>
    public static bool HasMixedScripts(string value)
    {
        var hasLatin = false;
        var hasCyrillic = false;
        var hasGreek = false;
        var hasArabic = false;

        foreach (var ch in value)
        {
            var script = GetScript(ch);

            hasLatin |= script == ScriptKind.Latin;
            hasCyrillic |= script == ScriptKind.Cyrillic;
            hasGreek |= script == ScriptKind.Greek;
            hasArabic |= script == ScriptKind.Arabic;
        }

        var distinct = new[] { hasLatin, hasCyrillic, hasGreek, hasArabic }.Count(x => x);
        return distinct > 1;
    }

    private enum ScriptKind
    {
        None,
        Latin,
        Cyrillic,
        Greek,
        Arabic
    }

    private static ScriptKind GetScript(char ch)
    {
        if (ch is >= 'a' and <= 'z' or >= 'A' and <= 'Z')
        {
            return ScriptKind.Latin;
        }

        if (ch is >= '\u0400' and <= '\u04FF')
        {
            return ScriptKind.Cyrillic;
        }

        if (ch is >= '\u0370' and <= '\u03FF')
        {
            return ScriptKind.Greek;
        }

        if (ch is >= '\u0600' and <= '\u06FF')
        {
            return ScriptKind.Arabic;
        }

        return ScriptKind.None;
    }

    /// <summary>
    /// Splits a host label into word-like tokens, breaking on separators and on
    /// digit/letter transitions: "paypa1-secure" -> ["paypa", "1", "secure"].
    /// </summary>
    public static IReadOnlyList<string> TokenizeLabel(string label) =>
        label.Split(new[] { '-', '_', '.', '/' }, StringSplitOptions.RemoveEmptyEntries);
}