using VulWall.Dashboard.Common.Models;

namespace VulWall.Dashboard.Recommendations.Models;

/// <summary>
/// Model for the _FindingsList partial view
/// </summary>
public class FindingsListModel
{
    public List<GroupedFindingViewModel> Findings { get; set; } = [];
    public FeatureAccess FeatureAccess { get; set; } = FeatureAccess.Full;
}
