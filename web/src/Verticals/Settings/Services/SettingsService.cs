using VulWall.Dashboard.Data.Entities.Organization;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Settings.Extensions;
using VulWall.Dashboard.Settings.Models;

namespace VulWall.Dashboard.Settings.Services;

public class SettingsService(
    OrganizationRepository organizationRepository,
    StripePaymentService.StripePaymentService stripePaymentService)
{
    public async Task<BillingDataViewModel> GetBillingDataAsync(Organization organization)
    {
        var paymentInfoTask = !string.IsNullOrEmpty(organization.Plan?.StripeSubscriptionId)
            ? stripePaymentService.GetSubscriptionPaymentMethodAsync(organization.Plan.StripeSubscriptionId)
            : Task.FromResult<PaymentMethodInfo?>(null);

        var recentInvoicesTask = !string.IsNullOrEmpty(organization.Plan?.StripeCustomerId)
            ? stripePaymentService.GetRecentInvoicesAsync(organization.Plan.StripeCustomerId)
            : Task.FromResult(new List<InvoiceInfo>());

        await Task.WhenAll(paymentInfoTask, recentInvoicesTask);

        var paymentInfo = await paymentInfoTask;
        var recentInvoices = await recentInvoicesTask;
        var (currentPlan, pendingPlan) = GetPlanInfo(organization);

        return new BillingDataViewModel
        {
            SubscriptionStatus = organization.Plan?.SubscriptionStatus,
            NextBillingDate = organization.Plan?.SubscriptionCancelAtPeriodEnd == true
                ? null
                : organization.Plan?.SubscriptionCurrentPeriodEnd,
            SubscriptionPeriodEnd = organization.Plan?.SubscriptionCurrentPeriodEnd,
            CancelAtPeriodEnd = organization.Plan?.SubscriptionCancelAtPeriodEnd ?? false,
            PaymentMethodLast4 = paymentInfo?.Last4,
            PaymentMethodBrand = paymentInfo?.Brand,
            CurrentPlan = currentPlan,
            BillingInterval = organization.Plan?.BillingInterval ?? "month",
            RecentInvoices = recentInvoices,
            PendingSubscriptionPlanInfo = pendingPlan
        };
    }

    public PlansDataViewModel GetPlansData(Organization organization)
    {
        var availablePlans = Plans.GetAvailablePlans();
        var (currentPlan, pendingPlan) = GetPlanInfo(organization);

        return new PlansDataViewModel
        {
            AvailablePlans = availablePlans,
            CurrentPlan = currentPlan,
            SubscriptionStatus = organization.Plan?.SubscriptionStatus,
            CancelAtPeriodEnd = organization.Plan?.SubscriptionCancelAtPeriodEnd ?? false,
            SubscriptionPeriodEnd = organization.Plan?.SubscriptionCurrentPeriodEnd,
            PendingSubscriptionPlanInfo = pendingPlan,
            BillingInterval = organization.Plan?.BillingInterval ?? "month"
        };
    }

    public async Task UpdateCompanyInfoAsync(string organizationId, string? companyName, string? industry, string? website)
    {
        var organization = await organizationRepository.GetByIdAsync(organizationId);
        if (organization == null)
            throw new InvalidOperationException($"Organization not found: {organizationId}");

        organization.CompanyName = companyName;
        organization.Industry = industry;
        organization.Website = website;
        organization.UpdatedAt = DateTime.UtcNow;

        await organizationRepository.UpdateAsync(organization);
    }

    public async Task UpdateLogoAsync(string organizationId, byte[] logoBytes)
    {
        var organization = await organizationRepository.GetByIdAsync(organizationId);
        if (organization == null)
            throw new InvalidOperationException($"Organization not found: {organizationId}");

        organization.Logo = logoBytes;
        organization.UpdatedAt = DateTime.UtcNow;

        await organizationRepository.UpdateAsync(organization);
    }

    public async Task RemoveLogoAsync(string organizationId)
    {
        var organization = await organizationRepository.GetByIdAsync(organizationId);
        if (organization == null)
            throw new InvalidOperationException($"Organization not found: {organizationId}");

        organization.Logo = null;
        organization.UpdatedAt = DateTime.UtcNow;

        await organizationRepository.UpdateAsync(organization);
    }

    public async Task MarkTourCompletedAsync(string organizationId)
    {
        var organization = await organizationRepository.GetByIdAsync(organizationId);
        if (organization == null)
            throw new InvalidOperationException($"Organization not found: {organizationId}");

        organization.TourCompleted = true;
        organization.UpdatedAt = DateTime.UtcNow;

        await organizationRepository.UpdateAsync(organization);
    }

    public async Task ResetTourAsync(string organizationId)
    {
        var organization = await organizationRepository.GetByIdAsync(organizationId);
        if (organization == null)
            throw new InvalidOperationException($"Organization not found: {organizationId}");

        organization.TourCompleted = false;
        organization.UpdatedAt = DateTime.UtcNow;

        await organizationRepository.UpdateAsync(organization);
    }

    private (PlanInfo currentPlan, PlanInfo? pendingPlan) GetPlanInfo(Organization organization)
    {
        PlanInfo? pendingPlan = null;
        if (organization.Plan?.SubscriptionStatus.IsIncomplete() == true &&
            !string.IsNullOrEmpty(organization.Plan?.SubscriptionPlan))
        {
            pendingPlan = Plans.GetPlanByName(organization.Plan.SubscriptionPlan);
        }

        var currentPlanName = organization.Plan?.IsActive == true
            ? organization.Plan.SubscriptionPlan ?? "Free"
            : "Free";
        var currentPlan = Plans.GetPlanByName(currentPlanName);

        return (currentPlan, pendingPlan);
    }
}
