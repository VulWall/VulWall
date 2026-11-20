using VulWall.Dashboard.Common.Models;
using VulWall.Dashboard.Reports.Models;
using VulWall.Dashboard.Scans.Models;

namespace VulWall.Dashboard.Dashboard.Models;

public class IndexViewModel
{
    // Feature access based on subscription tier
    public FeatureAccess FeatureAccess { get; set; } = FeatureAccess.Full;

    // Header
    public string PrimaryDomain { get; set; } = string.Empty;
    public string LastScanTimeAgo { get; set; } = string.Empty;
    public ScanNowState ScanNowState { get; set; }

    // Score hero
    public string ScoreBand { get; set; } = string.Empty;    // Excellent | Good | Needs attention | Poor | Critical
    public string ScoreVerdict { get; set; } = string.Empty; // one-sentence explanation of the current score

    // Stats
    public int TotalAssets { get; set; }
    public int CriticalIssues { get; set; }
    public int CriticalIssuesTrend { get; set; }
    public int HighIssues { get; set; }
    public int HighIssuesTrend { get; set; }
    public int DiscoveredAssets { get; set; }
    public int DiscoveredAssetsTrend { get; set; }
    public bool HasScanData { get; set; }
    public int SecurityScore { get; set; }
    public int SecurityScoreTrend { get; set; }

    // Security Score Breakdown (for detailed explanations)
    public List<ScoreBreakdownItem> SecurityScoreBreakdown { get; set; } = [];
    public ScoreSummary SecurityScoreSummary { get; set; } = new();
    public ScoreCap? SecurityScoreCap { get; set; }

    // Chart Data
    public IssuesTimelineChartData ChartData { get; set; } = new();

    // Critical Vulnerabilities
    public List<VulnerabilityItemViewModel> CriticalVulnerabilities { get; set; } = new();

    // Recent Scans
    public List<RecentScanViewModel> RecentScans { get; set; } = new();
}

public class VulnerabilityItemViewModel
{
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty; // Critical, High, Medium, Low
    public int AffectedAssetsCount { get; set; }
    public string DetailsUrl { get; set; } = "#";
    public int FindingsCount { get; set; } = 1; // Number of grouped findings
    public DateTime? LastDetected { get; set; }

    // Badge fields (matching Recommendations page)
    public bool IsNew { get; set; }
    public bool? IsExploitable { get; set; }
    public string? FindingType { get; set; }
    public string? OwaspCategory { get; set; }

    // AI Recommendation fields
    public string? VulnerabilityExplanation { get; set; }
    public string? PotentialImpact { get; set; }
    public List<string>? RemediationSteps { get; set; }
    public string? EstimatedEffort { get; set; }
    public string? Priority { get; set; }

    // One-click mute support: populated only when the grouped finding maps to a single
    // discovery (AffectedAssetsCount == 1), so the Overview can submit a suppression form
    // directly without sending the user to the detail page to pick an asset.
    public string? DiscoveryId { get; set; }
    public bool CanOneClickMute { get; set; }
}

public class RecentScanViewModel
{
    public string AssetName { get; set; } = string.Empty;
    public string TimeAgo { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty; // Critical, High, Medium, Low, Clean
    public int IssuesCount { get; set; }
    public string Summary { get; set; } = string.Empty;

    // Severity breakdown
    public int CriticalCount { get; set; }
    public int HighCount { get; set; }
    public int MediumCount { get; set; }
    public int LowCount { get; set; }
}
