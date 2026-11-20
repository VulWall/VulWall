namespace VulWall.Dashboard.Reports.Models;

public class IndexViewModel
{
    public List<ScanSelectItem> Scans { get; set; } = new();
    public string? SelectedScanId { get; set; }
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
