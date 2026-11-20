namespace VulWall.Dashboard.Settings.Models;

public sealed record BillingDataViewModel
{
    public string? SubscriptionStatus { get; init; }
    public DateTime? NextBillingDate { get; init; }
    public DateTime? SubscriptionPeriodEnd { get; init; }
    public bool CancelAtPeriodEnd { get; init; }
    public string? PaymentMethodLast4 { get; init; }
    public string? PaymentMethodBrand { get; init; }
    public PlanInfo? CurrentPlan { get; init; }
    public List<InvoiceInfo> RecentInvoices { get; init; } = [];
    public string BillingInterval { get; init; } = "month";
    public PlanInfo? PendingSubscriptionPlanInfo { get; init; }
}
