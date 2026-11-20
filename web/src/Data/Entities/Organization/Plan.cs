using MongoDB.Bson.Serialization.Attributes;
using VulWall.Dashboard.Settings.Extensions;

namespace VulWall.Dashboard.Data.Entities.Organization;

/// <summary>
/// Plan entity - represents subscription/billing information for an organization
/// </summary>
[BsonIgnoreExtraElements]
public class Plan
{
    /// <summary>
    /// Stripe customer ID for billing
    /// </summary>
    [BsonElement("stripe_customer_id")]
    public string? StripeCustomerId { get; set; }

    /// <summary>
    /// Stripe subscription ID
    /// </summary>
    [BsonElement("stripe_subscription_id")]
    public string? StripeSubscriptionId { get; set; }

    /// <summary>
    /// Subscription plan (Basic, Pro, Enterprise, etc.)
    /// </summary>
    [BsonElement("subscription_plan")]
    public string? SubscriptionPlan { get; set; }

    /// <summary>
    /// Current period start date (UTC)
    /// </summary>
    [BsonElement("subscription_current_period_start")]
    public DateTime? SubscriptionCurrentPeriodStart { get; set; }

    /// <summary>
    /// Current period end date / next billing date (UTC)
    /// </summary>
    [BsonElement("subscription_current_period_end")]
    public DateTime? SubscriptionCurrentPeriodEnd { get; set; }

    /// <summary>
    /// Billing interval: "month" or "year"
    /// </summary>
    [BsonElement("billing_interval")]
    public string BillingInterval { get; set; } = "month";

    /// <summary>
    /// Whether subscription will cancel at period end
    /// </summary>
    [BsonElement("subscription_cancel_at_period_end")]
    public bool SubscriptionCancelAtPeriodEnd { get; set; }

    /// <summary>
    /// Stripe subscription status (active, past_due, canceled, unpaid, etc.)
    /// </summary>
    [BsonElement("subscription_status")]
    public string? SubscriptionStatus { get; set; }

    /// <summary>
    /// Computed property: Returns true if subscription is currently active (period end is in the future)
    /// Includes past_due status as active since users retain access during Stripe's payment retry period
    /// </summary>
    [BsonIgnore]
    public bool IsActive =>
        (SubscriptionStatus.IsActive() || SubscriptionStatus.IsPastDue()) &&
        SubscriptionCurrentPeriodEnd.HasValue &&
        SubscriptionCurrentPeriodEnd.Value > DateTime.UtcNow;
}