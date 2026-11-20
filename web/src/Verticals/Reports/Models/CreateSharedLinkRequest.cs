namespace VulWall.Dashboard.Reports.Models;

public class CreateSharedLinkRequest
{
    public string ReportName { get; set; } = string.Empty;
    public string ScanId { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public int ExpirationDays { get; set; }
}
