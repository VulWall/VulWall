namespace VulWall.Dashboard.Settings.Models;

public class InvoiceInfo
{
    public string Id { get; set; } = string.Empty;
    public DateTime Created { get; set; }
    public DateTime? DueDate { get; set; }
    public decimal Amount { get; set; }
    public string Status { get; set; } = string.Empty;
    public string? PlanName { get; set; }
    public string? InvoicePdfUrl { get; set; }
}
