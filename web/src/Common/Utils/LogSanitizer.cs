using System.Globalization;
using System.Text;

namespace VulWall.Dashboard.Common.Utils;

/// <summary>
/// Makes request data (paths, route values) safe to write to the log. Anyone can send a request,
/// and the log is read in a terminal: a raw value could forge log lines with newlines or send
/// terminal escape sequences. Control, format and unassigned characters and line/paragraph
/// separators become '?', and long values are cut.
/// </summary>
public static class LogSanitizer
{
    public const int MaxLength = 200;

    public static string Clean(string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            return string.Empty;
        }

        var sb = new StringBuilder(Math.Min(value.Length, MaxLength + 3));
        foreach (var rune in value.EnumerateRunes())
        {
            if (sb.Length >= MaxLength)
            {
                return sb.Append("...").ToString();
            }

            sb.Append(IsUnsafe(rune) ? "?" : rune.ToString());
        }

        return sb.ToString();
    }

    private static bool IsUnsafe(Rune rune) =>
        // EnumerateRunes yields U+FFFD for a lone surrogate.
        rune == Rune.ReplacementChar
        || Rune.GetUnicodeCategory(rune) is UnicodeCategory.Control
            or UnicodeCategory.Format
            or UnicodeCategory.PrivateUse
            or UnicodeCategory.OtherNotAssigned
            or UnicodeCategory.LineSeparator
            or UnicodeCategory.ParagraphSeparator;
}
