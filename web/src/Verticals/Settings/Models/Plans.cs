using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Data.Entities.Organization;

namespace VulWall.Dashboard.Settings.Models;

public static class Plans
{
    private static readonly List<PlanInfo> AvailablePlans =
    [
        new()
        {
            Name = "Free",
            DisplayName = "Free Plan",
            Price = 0,
            Currency = "EUR",
            BillingPeriod = "month",
            StripePriceId = null,
            Description = "Do I have a problem?",
            MaxAssets = 1,
            DefaultScanCron = "0 3 15 * *", // Monthly on 15th at 3 AM
            Features =
            [
                "Full vulnerability scanning - all severities",
                "AI-powered remediation guidance",
                "Summary and technical reports",
                "Security score",
                "Email alerts for new findings",
                "1 domain (root only)"
            ]
        },

        new()
        {
            Name = "Pro",
            DisplayName = "Pro Plan",
            Price = 99,
            Currency = "EUR",
            BillingPeriod = "month",
            StripePriceId = ServiceSettings.Instance.StripeProPriceId,
            StripeAnnualPriceId = ServiceSettings.Instance.StripeProAnnualPriceId,
            AnnualPrice = 948,
            Description = "How do I fix and prove it?",
            MaxAssets = 5,
            DefaultScanCron = "0 3 * * 1", // Weekly on Monday at 3 AM
            Features =
            [
                "5 domains + full subdomain discovery",
                "Weekly + on-demand scans",
                "Shareable security certificate",
                "On-demand shared reports",
                "Embeddable trust badge",
                "Scan history and trend tracking",
                "Priority support"
            ]
        }
    ];

    public static List<PlanInfo> GetAvailablePlans() => AvailablePlans;

    public static PlanInfo? GetPlanByName(string planName)
    {
        return AvailablePlans.FirstOrDefault(p =>
            p.Name.Equals(planName, StringComparison.OrdinalIgnoreCase));
    }

    public static PlanInfo? GetPlanByStripePriceId(string stripePriceId)
    {
        return AvailablePlans.FirstOrDefault(p =>
            p.StripePriceId == stripePriceId || p.StripeAnnualPriceId == stripePriceId);
    }

    public static SubscriptionSettings GetDefaultSubscriptionSettings()
    {
        var freePlan = GetPlanByName("Free");
        return freePlan?.ToSubscriptionSettings() ?? new SubscriptionSettings
        {
            MaxAssets = 1,
            ScanCron = "0 3 15 * *"
        };
    }

    public static SubscriptionSettings? GetSubscriptionSettingsForPlan(string planName)
    {
        return GetPlanByName(planName)?.ToSubscriptionSettings();
    }
}