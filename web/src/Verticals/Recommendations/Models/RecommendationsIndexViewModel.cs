namespace VulWall.Dashboard.Recommendations.Models;

public class RecommendationsIndexViewModel
{
    public List<GroupedFindingViewModel> CriticalFindings { get; set; } = [];
    public List<GroupedFindingViewModel> HighFindings { get; set; } = [];
    public List<GroupedFindingViewModel> MediumFindings { get; set; } = [];
    public List<GroupedFindingViewModel> LowFindings { get; set; } = [];

    /// <summary>
    /// Findings that have been suppressed (false positive or accepted risk).
    /// </summary>
    public List<DismissedFindingViewModel> DismissedFindings { get; set; } = [];

    // Total unique CVEs
    public int TotalFindings => CriticalFindings.Count + HighFindings.Count + MediumFindings.Count + LowFindings.Count;

    // Total affected assets
    public int TotalAffectedAssets => CriticalFindings.Sum(f => f.AffectedAssets.Count) +
                                       HighFindings.Sum(f => f.AffectedAssets.Count) +
                                       MediumFindings.Sum(f => f.AffectedAssets.Count) +
                                       LowFindings.Sum(f => f.AffectedAssets.Count);

    /// <summary>
    /// All open findings flattened in severity order (critical first).
    /// </summary>
    public IEnumerable<GroupedFindingViewModel> AllFindings =>
        CriticalFindings.Concat(HighFindings).Concat(MediumFindings).Concat(LowFindings);

    // Findings an attacker can exploit right now.
    public int ExploitableCount => AllFindings.Count(f => f.IsExploitable == true);

    // Low-effort fixes ("trivial" or "small" in the KB vocabulary).
    public int QuickWinCount => AllFindings.Count(f =>
        string.Equals(f.EstimatedEffort, "trivial", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(f.EstimatedEffort, "small", StringComparison.OrdinalIgnoreCase));

    // Findings that already have an AI-generated remediation.
    public int AiReadyCount => AllFindings.Count(f => f.HasAIRecommendation);

    /// <summary>
    /// Timestamp of the latest completed scan, used for the "last scan" header hint.
    /// </summary>
    public DateTime? LastScanAt { get; set; }
}
