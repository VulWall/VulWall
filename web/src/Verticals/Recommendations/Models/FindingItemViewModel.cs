using VulWall.Dashboard.Common.Contracts.Enums;

namespace VulWall.Dashboard.Recommendations.Models;

/// <summary>
/// View model for finding details (AI recommendation content)
/// Discovery/target info is now in AffectedAssetDetail
/// </summary>
public class FindingItemViewModel
{
    public string Id { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public Severity Severity { get; set; }
    public string? FindingType { get; set; }
    public string? BusinessImpact { get; set; }

    // AI Recommendation fields
    public string? VulnerabilityExplanation { get; set; }
    public string? PotentialImpact { get; set; }
    public List<string>? RemediationSteps { get; set; }
    public List<string>? BestPractices { get; set; }
    public string? EstimatedEffort { get; set; }
    public string? Priority { get; set; }
    public string? OwaspCategory { get; set; }
    public bool? IsExploitable { get; set; }
    public bool HasAIRecommendation => !string.IsNullOrEmpty(VulnerabilityExplanation) ||
                                        !string.IsNullOrEmpty(PotentialImpact) ||
                                        (RemediationSteps?.Count > 0);

    // New/Recurring badge support
    public bool IsNew { get; set; }
    public DateTime FirstDetected { get; set; }
    public DateTime LastDetected { get; set; }

    /// <summary>
    /// Discovery ID of the primary finding — used to pre-fill the suppress form on the detail page.
    /// </summary>
    public string? DiscoveryId { get; set; }

    // Reference identifiers and provenance (shown in the detail-page Details card)
    public string? Cve { get; set; }
    public string? Cwe { get; set; }
    public string? DetectedBy { get; set; }

    /// <summary>
    /// Reference URLs the scanner attached to the finding (metadata.reference). Shown as the
    /// fallback guidance when the finding type has no knowledge-base entry.
    /// </summary>
    public List<string> References { get; set; } = [];
    public string? Status { get; set; }
}
