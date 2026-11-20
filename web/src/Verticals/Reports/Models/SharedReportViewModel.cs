namespace VulWall.Dashboard.Reports.Models;

public class SharedReportViewModel
{
    public bool RequiresPassword { get; set; }
    public bool IsExpired { get; set; }
    public bool IsRevoked { get; set; }
    public bool NotFound { get; set; }
    public string? ErrorMessage { get; set; }
    public string? Token { get; set; }
    public SummaryReportViewModel? Report { get; set; }
}
