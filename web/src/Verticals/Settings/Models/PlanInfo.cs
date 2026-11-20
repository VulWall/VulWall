using VulWall.Dashboard.Data.Entities.Organization;

namespace VulWall.Dashboard.Settings.Models;

public class PlanInfo
{
    private static readonly Random Rng = new();

    public string Name { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public decimal Price { get; set; }
    public string Currency { get; set; } = "EUR";
    public string BillingPeriod { get; set; } = "month";
    public string? StripePriceId { get; set; }
    public string? StripeAnnualPriceId { get; set; }
    public decimal AnnualPrice { get; set; }
    public List<string> Features { get; set; } = new();
    public string Description { get; set; } = string.Empty;

    public int MaxAssets { get; set; }

    /// <summary>
    /// Cron template for display/documentation only. Actual cron is randomized per org.
    /// </summary>
    public string DefaultScanCron { get; set; } = string.Empty;

    /// <summary>
    /// Generates a subscription with a randomized scan cron to spread scanner load.
    /// Free: random minute, random hour, current day-of-month -- monthly on the day the user registers.
    /// Pro: random minute, random hour, random weekend night (Fri/Sat/Sun) -- weekly.
    /// </summary>
    public SubscriptionSettings ToSubscriptionSettings() => new()
    {
        MaxAssets = MaxAssets,
        ScanCron = GenerateRandomizedScanCron()
    };

    private static readonly int[] WeekendNights = [0, 5, 6]; // Sunday, Friday, Saturday

    private string GenerateRandomizedScanCron()
    {
        var minute = Rng.Next(0, 60);
        var hour = Rng.Next(0, 6); // 0-5 AM to keep scans in off-peak hours

        return Name switch
        {
            "Free" => $"{minute} {hour} {DateTime.UtcNow.Day} * *",
            "Pro" => $"{minute} {hour} * * {WeekendNights[Rng.Next(WeekendNights.Length)]}",
            _ => DefaultScanCron
        };
    }
}
