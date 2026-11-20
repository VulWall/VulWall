using VulWall.Dashboard.Common.Contracts.Enums;

namespace VulWall.Dashboard.Assets.Models;

public class AssetItemViewModel
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = "Unknown";
    public AssetType Type { get; set; }
    public bool Enabled { get; set; }
    public DateTime AddedOn { get; set; }
    public DateTime? DnsVerifiedAt { get; set; }
}
