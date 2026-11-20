namespace VulWall.Dashboard.Recommendations.Models;

public class DismissedFindingViewModel
{
    public string SuppressionId { get; set; } = string.Empty;
    public string DiscoveryId { get; set; } = string.Empty;
    public string FindingType { get; set; } = string.Empty;

    /// <summary>
    /// Raw status string: "false_positive" or "accepted_risk".
    /// </summary>
    public string Status { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable label ("False positive" / "Accepted risk").
    /// </summary>
    public string StatusLabel { get; set; } = string.Empty;

    public string? Note { get; set; }
    public string SuppressedBy { get; set; } = string.Empty;
    public DateTime SuppressedAt { get; set; }

    /// <summary>
    /// Resolved asset target (hostname / domain), falls back to discoveryId.
    /// </summary>
    public string Target { get; set; } = string.Empty;
}
