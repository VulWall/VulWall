using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Stripe;
using VulWall.Dashboard.Attributes;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Settings.Extensions;
using VulWall.Dashboard.Settings.Models;
using VulWall.Dashboard.Settings.Services.StripePaymentService;

namespace VulWall.Dashboard.Settings;

public class PaymentsController(
    ILogger<PaymentsController> logger,
    OrganizationRepository organizationRepository,
    IOrganizationContext organizationContext,
    StripePaymentService stripePaymentService)
    : Controller
{
    private const string FreePlanName = "Free";

    /// <summary>
    /// Creates a new subscription and returns client secret for Payment Element
    /// </summary>
    [HttpPost]
    [Authorize]
    [AuditLog(Category = AuditLogCategory.Billing, Action = "Subscribed to Pro Plan")]
    public async Task<IActionResult> CreateSubscription([FromBody] CreateSubscriptionRequest request)
    {
        var email = User.FindFirst(ClaimTypes.Email)?.Value;

        if (string.IsNullOrEmpty(email))
            return BadRequest("User not authenticated");

        var plan = Plans.GetPlanByName(request.PlanName);
        if (plan == null)
            return BadRequest($"Plan '{request.PlanName}' not found");

        if (plan.Name == FreePlanName)
            return BadRequest("Cannot create subscription for Free plan");

        var organization = await organizationContext.GetCurrentOrganizationAsync();

        if (!string.IsNullOrEmpty(organization.Plan?.StripeSubscriptionId))
        {
            var status = organization.Plan.SubscriptionStatus;

            if (status.IsIncomplete())
            {
                var planInfo = Plans.GetPlanByName(organization.Plan.SubscriptionPlan ?? "");
                return BadRequest(
                    $"You already have a pending {planInfo?.DisplayName ?? organization.Plan.SubscriptionPlan} subscription. Please complete the payment or wait for it to expire before creating a new subscription.");
            }

            if (!status.IsTerminated() && organization.Plan.IsActive)
            {
                return BadRequest(
                    "You already have an active subscription. Please cancel it before subscribing to a different plan.");
            }
        }

        try
        {
            var priceId = request.BillingInterval == "year"
                ? plan.StripeAnnualPriceId
                : plan.StripePriceId;

            if (string.IsNullOrEmpty(priceId))
                return BadRequest($"No price configured for {request.BillingInterval}ly billing");

            var result =
                await stripePaymentService.CreateSubscriptionAsync(email, organization.Id, priceId);

            organization.Plan ??= new Data.Entities.Organization.Plan();
            organization.Plan.SubscriptionPlan = plan.Name;
            organization.Plan.StripeCustomerId = result.CustomerId;
            organization.Plan.StripeSubscriptionId = result.SubscriptionId;
            organization.Plan.SubscriptionStatus = "incomplete";
            organization.UpdatedAt = DateTime.UtcNow;
            await organizationRepository.UpdateAsync(organization);

            return Ok(new
            {
                clientSecret = result.ClientSecret,
                subscriptionId = result.SubscriptionId
            });
        }
        catch (StripeException ex)
        {
            logger.LogError(ex, "Failed to create subscription for org {OrgId}", organization.Id);
            return StatusCode(500, "Failed to create subscription");
        }
    }

    /// <summary>
    /// Gets client secret for incomplete subscription to resume payment
    /// </summary>
    [HttpPost]
    [Authorize]
    public async Task<IActionResult> ResumeIncompleteSubscription()
    {
        var organization = await organizationContext.GetCurrentOrganizationAsync();
        if (organization.Plan?.StripeSubscriptionId == null)
            return BadRequest("No subscription found");

        if (organization.Plan.SubscriptionStatus != "incomplete")
            return BadRequest("Subscription is not incomplete");

        try
        {
            var clientSecret = await stripePaymentService.GetIncompleteSubscriptionClientSecretAsync(
                organization.Plan.StripeSubscriptionId);

            if (string.IsNullOrEmpty(clientSecret))
                return BadRequest("Unable to retrieve payment information. The subscription may have expired.");

            return Ok(new
            {
                clientSecret,
                subscriptionId = organization.Plan.StripeSubscriptionId
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to resume subscription for org {OrgId}", organization.Id);
            return StatusCode(500, "Failed to resume subscription");
        }
    }

    /// <summary>
    /// Changes subscription plan - takes effect at end of current billing period
    /// </summary>
    [HttpPost]
    [Authorize]
    [AuditLog(Category = AuditLogCategory.Billing, Action = "Changed Subscription Plan")]
    public async Task<IActionResult> ChangeSubscriptionPlan([FromBody] ChangeSubscriptionPlanRequest request)
    {
        var newPlan = Plans.GetPlanByName(request.PlanName);
        if (newPlan == null)
            return BadRequest($"Plan '{request.PlanName}' not found");

        var organization = await organizationContext.GetCurrentOrganizationAsync();

        // Check if already on this plan
        var currentPlan = organization.Plan?.SubscriptionPlan ?? FreePlanName;
        if (currentPlan == newPlan.Name)
            return BadRequest("Already subscribed to this plan");

        // Can't change plan if no active subscription (already on Free)
        if (string.IsNullOrEmpty(organization.Plan?.StripeSubscriptionId))
            return BadRequest("No active subscription to change. Please subscribe to a paid plan from the Plans tab.");

        try
        {
            if (newPlan.Name == FreePlanName)
            {
                // Downgrade to Free - cancel at period end
                var subscription =
                    await stripePaymentService.CancelSubscriptionAsync(organization.Plan.StripeSubscriptionId,
                        cancelNow: false);

                organization.Plan.SubscriptionCancelAtPeriodEnd = true;
                organization.Plan.SubscriptionStatus = subscription.Status;
                organization.Plan.SubscriptionCurrentPeriodEnd =
                    subscription.Items?.Data?.FirstOrDefault()?.CurrentPeriodEnd;
                organization.UpdatedAt = DateTime.UtcNow;
                await organizationRepository.UpdateAsync(organization);

                return Ok(new
                {
                    message = "Downgrade to Free plan scheduled successfully",
                    newPlan = FreePlanName,
                    effectiveDate = organization.Plan.SubscriptionCurrentPeriodEnd
                });
            }

            var newPriceId = request.BillingInterval == "year"
                ? newPlan.StripeAnnualPriceId
                : newPlan.StripePriceId;

            if (string.IsNullOrEmpty(newPriceId))
                return BadRequest($"No price configured for {request.BillingInterval}ly billing");

            await stripePaymentService.ChangeSubscriptionPlanAsync(organization.Plan.StripeSubscriptionId,
                newPriceId);

            return Ok(new
            {
                message = "Plan change scheduled successfully",
                newPlan = newPlan.Name,
                effectiveDate = organization.Plan.SubscriptionCurrentPeriodEnd
            });
        }
        catch (StripeException ex)
        {
            logger.LogError(ex, "Failed to change plan for org {OrgId}", organization.Id);
            return StatusCode(500, "Failed to change plan");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unexpected error changing plan for org {OrgId}", organization.Id);
            return StatusCode(500, "Failed to change plan");
        }
    }

    /// <summary>
    /// Cancels subscription - incomplete subscriptions are cancelled immediately, active ones at period end
    /// </summary>
    [HttpPost]
    [Authorize]
    [AuditLog(Category = AuditLogCategory.Billing, Action = "Cancelled Subscription")]
    public async Task<IActionResult> CancelSubscription()
    {
        var organization = await organizationContext.GetCurrentOrganizationAsync();
        if (organization.Plan?.StripeSubscriptionId == null)
            return BadRequest("No active subscription");

        try
        {
            var isIncomplete = organization.Plan.SubscriptionStatus.IsIncomplete();

            if (isIncomplete)
            {
                // Incomplete subscription - cancel now and switch to Free
                await stripePaymentService.CancelSubscriptionAsync(organization.Plan.StripeSubscriptionId,
                    cancelNow: true);

                //reset back to free plan
                organization.Plan.StripeSubscriptionId = null;
                organization.Plan.SubscriptionPlan = FreePlanName;
                organization.Plan.SubscriptionStatus = "active";
                organization.Plan.SubscriptionCurrentPeriodStart = null;
                organization.Plan.SubscriptionCurrentPeriodEnd = null;
                organization.Plan.SubscriptionCancelAtPeriodEnd = false;
                organization.SubscriptionSettings = Plans.GetDefaultSubscriptionSettings();
                organization.UpdatedAt = DateTime.UtcNow;
                await organizationRepository.UpdateAsync(organization);

                return Ok(new
                {
                    message = "Incomplete subscription cancelled",
                    immediate = true
                });
            }

            // Active subscription - cancel at period end
            var subscription =
                await stripePaymentService.CancelSubscriptionAsync(organization.Plan.StripeSubscriptionId,
                    cancelNow: false);

            organization.Plan.SubscriptionCancelAtPeriodEnd = true;
            organization.Plan.SubscriptionStatus = subscription.Status;
            organization.Plan.SubscriptionCurrentPeriodEnd =
                subscription.Items?.Data?.FirstOrDefault()?.CurrentPeriodEnd;
            organization.UpdatedAt = DateTime.UtcNow;
            await organizationRepository.UpdateAsync(organization);

            return Ok(new
            {
                message = "Subscription cancelled successfully",
                effectiveDate = organization.Plan.SubscriptionCurrentPeriodEnd
            });
        }
        catch (StripeException ex)
        {
            logger.LogError(ex, "Failed to cancel subscription for org {OrgId}", organization.Id);
            return StatusCode(500, "Failed to cancel subscription");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unexpected error cancelling subscription for org {OrgId}", organization.Id);
            return StatusCode(500, "Failed to cancel subscription");
        }
    }

    /// <summary>
    /// Reactivates a cancelled subscription (removes cancel_at_period_end)
    /// </summary>
    [HttpPost]
    [Authorize]
    [AuditLog(Category = AuditLogCategory.Billing, Action = "Reactivated Subscription")]
    public async Task<IActionResult> ReactivateSubscription()
    {
        var organization = await organizationContext.GetCurrentOrganizationAsync();
        if (organization.Plan?.StripeSubscriptionId == null)
            return BadRequest("No subscription to reactivate");

        if (!organization.Plan.SubscriptionCancelAtPeriodEnd)
            return BadRequest("Subscription is not cancelled");

        try
        {
            var subscription =
                await stripePaymentService.ReactivateSubscriptionAsync(organization.Plan.StripeSubscriptionId);

            organization.Plan.SubscriptionCancelAtPeriodEnd = false;
            organization.Plan.SubscriptionStatus = subscription.Status;
            organization.UpdatedAt = DateTime.UtcNow;
            await organizationRepository.UpdateAsync(organization);

            return Ok(new
            {
                message = "Subscription reactivated successfully"
            });
        }
        catch (StripeException ex)
        {
            logger.LogError(ex, "Failed to reactivate subscription for org {OrgId}", organization.Id);
            return StatusCode(500, "Failed to reactivate subscription");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unexpected error reactivating subscription for org {OrgId}", organization.Id);
            return StatusCode(500, "Failed to reactivate subscription");
        }
    }

    /// <summary>
    /// Stripe webhook endpoint - receives payment events
    /// </summary>
    [HttpPost]
    [AllowAnonymous]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Webhook()
    {
        string json;
        using (var reader = new StreamReader(Request.Body))
        {
            json = await reader.ReadToEndAsync();
        }

        var signature = Request.Headers["Stripe-Signature"].ToString();

        try
        {
            var webhookSecret = ServiceSettings.Instance.StripeWebhookSecret;
            var stripeEvent =
                EventUtility.ConstructEvent(json, signature, webhookSecret, throwOnApiVersionMismatch: false);

            await stripePaymentService.HandleWebhookEvent(stripeEvent);

            return Ok();
        }
        catch (StripeException ex)
        {
            logger.LogError(ex, "Webhook verification failed");
            return BadRequest();
        }
    }

}