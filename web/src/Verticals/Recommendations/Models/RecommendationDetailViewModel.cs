using VulWall.Dashboard.Common.Models;

namespace VulWall.Dashboard.Recommendations.Models;

public class RecommendationDetailViewModel
{
    public FindingItemViewModel Finding { get; set; } = null!;

    /// <summary>
    /// All affected assets for this CVE (same Title)
    /// </summary>
    public List<AffectedAssetDetail> AffectedAssets { get; set; } = [];

    /// <summary>
    /// Feature access based on subscription tier
    /// </summary>
    public FeatureAccess FeatureAccess { get; set; } = FeatureAccess.Full;

    /// <summary>
    /// True when ANTHROPIC_API_KEY is not set, so the page can explain how to get AI guidance.
    /// </summary>
    public bool ShowAiKeyHint { get; set; }
}
