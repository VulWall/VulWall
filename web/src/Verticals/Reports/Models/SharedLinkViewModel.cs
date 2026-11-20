namespace VulWall.Dashboard.Reports.Models;

public class SharedLinkViewModel
{
    public string Id { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
    public string ReportName { get; set; } = string.Empty;
    public string ScanName { get; set; } = string.Empty;
    public string Type { get; set; } = string.Empty;
    public DateTime Created { get; set; }
    public string Expires { get; set; } = string.Empty;
    public bool IsExpired { get; set; }
    public bool IsRevoked { get; set; }
    public string TypeBadgeClass { get; set; } = string.Empty;

    public bool IsActive => !IsExpired && !IsRevoked;
}