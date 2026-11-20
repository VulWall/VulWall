namespace VulWall.Dashboard.Recommendations.Models;

public class RecommendationDetailViewModel
{
    public FindingItemViewModel Finding { get; set; } = null!;

    /// <summary>
    /// All affected assets for this CVE (same Title)
    /// </summary>
    public List<AffectedAssetDetail> AffectedAssets { get; set; } = [];

    /// <summary>
    /// True when ANTHROPIC_API_KEY is not set, so the page can explain how to get AI guidance.
    /// </summary>
    public bool ShowAiKeyHint { get; set; }
}
