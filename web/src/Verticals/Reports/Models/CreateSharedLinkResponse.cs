namespace VulWall.Dashboard.Reports.Models;

public class CreateSharedLinkResponse
{
    public bool Success { get; set; }
    public string? LinkId { get; set; }
    public string? Token { get; set; }
    public string? ShareableUrl { get; set; }
    public string? Error { get; set; }
}
