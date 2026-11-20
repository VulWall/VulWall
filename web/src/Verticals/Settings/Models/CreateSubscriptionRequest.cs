namespace VulWall.Dashboard.Settings.Models;

public class CreateSubscriptionRequest
{
    public string PlanName { get; set; } = string.Empty;
    public string BillingInterval { get; set; } = "month"; // "month" | "year"
}
