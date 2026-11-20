namespace VulWall.Dashboard.Reports.Models;

public record RecentActivityViewModel
{
    public string Action { get; init; } = string.Empty;
    public string UserName { get; init; } = string.Empty;
    public string? AdditionalInfo { get; init; }
    public string TimeAgo { get; init; } = string.Empty;
}