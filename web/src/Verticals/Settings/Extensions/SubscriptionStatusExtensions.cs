namespace VulWall.Dashboard.Settings.Extensions;

public static class SubscriptionStatusExtensions
{
    public static bool IsIncomplete(this string? status)
        => status == "incomplete";

    public static bool IsActive(this string? status)
        => status == "active";
    
    public static bool IsPastDue(this string? status)
        => status == "past_due";

    public static bool IsTerminated(this string? status)
        => status is "canceled" or "incomplete_expired" or "unpaid";
}
