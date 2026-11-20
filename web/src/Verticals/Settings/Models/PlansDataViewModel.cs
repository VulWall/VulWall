namespace VulWall.Dashboard.Settings.Models;

public sealed record PlansDataViewModel
{
    public List<PlanInfo> AvailablePlans { get; init; } = [];
    public PlanInfo? CurrentPlan { get; init; }
    public string? SubscriptionStatus { get; init; }
    public bool CancelAtPeriodEnd { get; init; }
    public DateTime? SubscriptionPeriodEnd { get; init; }
    public PlanInfo? PendingSubscriptionPlanInfo { get; init; }
    public string BillingInterval { get; init; } = "month";
}
