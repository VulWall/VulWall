using VulWall.Dashboard.Common.Contracts.Enums;

namespace VulWall.Dashboard.Discoveries.Models;

public class DiscoveryItemViewModel
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = "Unknown";
    public AssetType Type { get; set; }
    public AssetStatus Status { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    public string? ParentId { get; set; }
    public string? IpAddress { get; set; }
    public List<DiscoveryItemViewModel> Children { get; set; } = [];
    public Dictionary<string, object?> Metadata { get; set; } = new();
    public int PortsCount { get; set; }
    public int ServicesCount { get; set; }
    public int CriticalIssues { get; set; }
    public int HighIssues { get; set; }
    public int MediumIssues { get; set; }
    public int LowIssues { get; set; }
    public List<PortInfo> Ports { get; set; } = [];
    public OwnershipStatus OwnershipStatus { get; set; }

    // Geographic and hosting information (extracted from Metadata)
    public string? CountryCode { get; set; }
    public string? Continent { get; set; }
    public string? Isp { get; set; }
    public string? CloudProvider { get; set; }
    public string? CloudRegion { get; set; }
    public string? Waf { get; set; }
    public string? CdnEdge { get; set; }

    public List<ServiceGroup> GroupedServices
    {
        get
        {
            return Ports
                .Where(p => p.Service != "unknown")
                .GroupBy(p => p.Service)
                .Select(g => new ServiceGroup
                {
                    ServiceName = g.Key,
                    Ports = string.Join(", ", g.Select(p => p.PortNumber).OrderBy(p => p)),
                    Count = g.Count()
                })
                .OrderBy(s => s.ServiceName)
                .ToList();
        }
    }
}

public class PortInfo
{
    public int PortNumber { get; set; }
    public string Protocol { get; set; } = string.Empty;
    public string Service { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public int IpCount { get; set; } = 1;
}

public class ServiceGroup
{
    public string ServiceName { get; set; } = string.Empty;
    public string Ports { get; set; } = string.Empty;
    public int Count { get; set; }
}
