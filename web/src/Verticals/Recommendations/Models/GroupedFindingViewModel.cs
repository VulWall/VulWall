using VulWall.Dashboard.Common.Contracts.Enums;

namespace VulWall.Dashboard.Recommendations.Models;

public class GroupedFindingViewModel
{
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public Severity Severity { get; set; }
    public string? FindingType { get; set; }
    public string? BusinessImpact { get; set; }
    public string? EstimatedEffort { get; set; }
    public string? OwaspCategory { get; set; }
    public bool? IsExploitable { get; set; }
    public DateTime FirstDetected { get; set; }
    public DateTime LastDetected { get; set; }
    public bool HasAIRecommendation { get; set; }
    public bool IsNew { get; set; }

    // First finding ID for detail link
    public string PrimaryFindingId { get; set; } = string.Empty;

    // Affected assets
    public List<AffectedAsset> AffectedAssets { get; set; } = [];
}

public class AffectedAsset
{
    public string FindingId { get; set; } = string.Empty;
    public string? DiscoveryId { get; set; }
    public string? Target { get; set; }
    public int? Port { get; set; }
}

/// <summary>
/// Detailed affected asset information for the detail view
/// </summary>
public class AffectedAssetDetail
{
    public string FindingId { get; set; } = string.Empty;
    public string? DiscoveryId { get; set; }
    public string? Target { get; set; }
    public string? Ip { get; set; }
    public int? Port { get; set; }
    public string? Protocol { get; set; }
    public string? ServiceName { get; set; }
    public DateTime FirstDetected { get; set; }
    public DateTime LastDetected { get; set; }
    public bool IsSuppressed { get; set; }
    public string? SuppressionId { get; set; }
    public string? SuppressionStatus { get; set; }
}
