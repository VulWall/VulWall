using VulWall.Dashboard.Common.Models;

namespace VulWall.Dashboard.Discoveries.Models;

public class IndexViewModel
{
    // Feature access based on subscription tier
    public FeatureAccess FeatureAccess { get; set; } = FeatureAccess.Free;

    // Visible discoveries based on subscription tier (free: root domains, pro: all)
    public List<DiscoveryItemViewModel> Discoveries { get; set; } = [];

    // Summary stats for teaser (always populated)
    public int TotalDiscoveries { get; set; }
    public int DomainCount { get; set; }
    public int SubdomainCount { get; set; }
    public int IpCount { get; set; }
    public int PortCount { get; set; }
}
