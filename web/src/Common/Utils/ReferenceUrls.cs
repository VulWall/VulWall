using MongoDB.Bson;

namespace VulWall.Dashboard.Common.Utils;

/// <summary>
/// Reference links of a finding. The values come from scanner output (nuclei templates, advisory
/// feeds) and are rendered as links, so only absolute http/https URLs pass; anything else
/// (<c>javascript:</c>, <c>data:</c>, relative paths) is dropped.
/// </summary>
public static class ReferenceUrls
{
    public const int MaxReferences = 10;

    /// <summary>
    /// Collects reference URLs from the finding's top-level <c>references</c> field and, for
    /// findings written before the scanner stored that field, from <c>metadata.reference</c> /
    /// <c>metadata.references</c> (a string, an array or null).
    /// </summary>
    public static List<string> Extract(IEnumerable<string>? references, BsonDocument? metadata)
    {
        var candidates = new List<string>(references ?? []);
        foreach (var key in metadata == null ? [] : new[] { "reference", "references" })
        {
            if (!metadata!.TryGetValue(key, out var value))
                continue;
            if (value.IsString)
                candidates.Add(value.AsString);
            else if (value.IsBsonArray)
                candidates.AddRange(value.AsBsonArray.Where(v => v.IsString).Select(v => v.AsString));
        }

        return candidates
            .Select(c => c.Trim())
            .Where(IsHttpUrl)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(MaxReferences)
            .ToList();
    }

    public static bool IsHttpUrl(string candidate) =>
        Uri.TryCreate(candidate, UriKind.Absolute, out var uri)
        && (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp);
}
