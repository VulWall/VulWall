using System.Security.Claims;
using VulWall.Dashboard.Common.Contracts.Models;

namespace VulWall.Dashboard.Settings.Models;

public sealed record AccountUserViewModel
{
    public string? FirstName   { get; init; }
    public string? LastName    { get; init; }
    public string? FullName    { get; init; }
    public string? Company     { get; init; }
    public string? Industry    { get; init; }
    public string? Website     { get; init; }
    public string? OwnerEmail  { get; init; }
    public string? OrgId       { get; init; }
    public bool HasLogo        { get; init; }

    // Subscription fields
    public string? SubscriptionStatus { get; init; }
    public DateTime? NextBillingDate { get; init; }
    public DateTime? SubscriptionPeriodEnd { get; init; }
    public bool CancelAtPeriodEnd { get; init; }
    public string? PaymentMethodLast4 { get; init; }
    public string? PaymentMethodBrand { get; init; }

    // Available plans
    public List<PlanInfo> AvailablePlans { get; init; } = [];
    public PlanInfo? CurrentPlan { get; init; }

    // Billing history
    public List<InvoiceInfo> RecentInvoices { get; init; } = [];

    // Pending subscription (incomplete)
    public PlanInfo? PendingSubscriptionPlanInfo { get; init; }

    public static AccountUserViewModel FromClaims(ClaimsPrincipal user)
    {
        return new AccountUserViewModel
        {
            FirstName = user.FindFirst(ClaimTypes.GivenName)?.Value,
            LastName  = user.FindFirst(ClaimTypes.Surname)?.Value,
            FullName  = user.FindFirst("name")?.Value ?? user.Identity?.Name,
            Company   = null,
            Industry  = null,
            Website   = null,
            OrgId     = null
        };
    }
}