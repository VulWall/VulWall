using VulWall.Dashboard.Common.Models;

namespace VulWall.Dashboard.Reports.Models;

public class IndexViewModel
{
    public List<SharedLinkViewModel> SharedLinks { get; set; } = new();
    public int ActiveLinksCount { get; set; }
    public int MaxLinksCount { get; set; }
    public string OrganizationId { get; set; } = string.Empty;
    public string CompanyName { get; set; } = string.Empty;
    public bool CertVisible { get; set; } = true;
    public List<ScanSelectItem> Scans { get; set; } = new();
    public string? SelectedScanId { get; set; }

    /// <summary>
    /// Feature access based on subscription tier
    /// </summary>
    public FeatureAccess FeatureAccess { get; set; } = FeatureAccess.Free;
}

public class ScanSelectItem
{
    public string Id { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public int FindingsCount { get; set; }
    public int Score { get; set; }
    public string Band { get; set; } = "";
    public int AssetsCount { get; set; }
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
    public int Info { get; set; }
}