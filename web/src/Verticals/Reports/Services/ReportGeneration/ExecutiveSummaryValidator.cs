using System.Text.RegularExpressions;

namespace VulWall.Dashboard.Reports.Services.ReportGeneration;

/// <summary>
/// Checks that an AI executive summary is the plain 2-3 sentence paragraph the report expects. A
/// rejected summary is stored as failed and the report renders without the AI section. The bounds are
/// loose on purpose: each failure is retried, and each retry is a paid call.
/// </summary>
public static partial class ExecutiveSummaryValidator
{
    public const int MinLength = 60;
    public const int MaxLength = 1200;
    public const int MaxSentences = 5;

    /// <summary>Returns why the summary is not usable, or null when it is.</summary>
    public static string? Validate(string? summary)
    {
        var text = summary?.Trim() ?? string.Empty;
        if (text.Length < MinLength)
            return $"too short ({text.Length} characters, minimum {MinLength})";
        if (text.Length > MaxLength)
            return $"too long ({text.Length} characters, maximum {MaxLength})";
        if (text[0] is '{' or '[' || text.Contains("\":"))
            return "looks like JSON";
        if (text.Contains("```") || text.Contains("**") || MarkdownLine().IsMatch(text))
            return "contains Markdown";

        var sentences = SentenceEnd().Count(text);
        if (sentences > MaxSentences)
            return $"{sentences} sentences, maximum {MaxSentences}";
        return null;
    }

    // A heading, list item or quote at the start of a line.
    [GeneratedRegex(@"^\s*(#{1,6}\s|[-*+>]\s|\d+[.)]\s)", RegexOptions.Multiline)]
    private static partial Regex MarkdownLine();

    // End punctuation followed by the end of the text, or by a space and a capital letter or a quote,
    // so "e.g. the" and "7.5" are not counted.
    [GeneratedRegex(@"[.!?]+[""')]?(?=\s+[A-Z""']|\s*$)")]
    private static partial Regex SentenceEnd();
}
