namespace VulWall.Dashboard.Discoveries.Models;

public class IndexViewModel
{
    // Root discoveries with their children
    public List<DiscoveryItemViewModel> Discoveries { get; set; } = [];

    // Summary stats
    public int TotalDiscoveries { get; set; }
    public int DomainCount { get; set; }
    public int SubdomainCount { get; set; }
    public int IpCount { get; set; }
    public int PortCount { get; set; }

    /// <summary>A scan is queued or running: "Rescan now" is disabled (the server refuses it too).</summary>
    public bool ScanInProgress { get; set; }
}
