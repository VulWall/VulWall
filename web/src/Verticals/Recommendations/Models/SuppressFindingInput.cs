using System.ComponentModel.DataAnnotations;

namespace VulWall.Dashboard.Recommendations.Models;

public class SuppressFindingInput
{
    public string DiscoveryId { get; set; } = string.Empty;
    public string FindingType { get; set; } = string.Empty;

    /// <summary>
    /// "false_positive" or "accepted_risk" — see <see cref="Constants.SuppressionStatus"/>.
    /// </summary>
    public string Status { get; set; } = string.Empty;

    [StringLength(500)]
    public string? Note { get; set; }
}

public class UnsuppressFindingInput
{
    public string SuppressionId { get; set; } = string.Empty;
}
