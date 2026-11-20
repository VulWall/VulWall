using Stripe;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Data.Entities;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Settings.Extensions;
using VulWall.Dashboard.Settings.Models;

namespace VulWall.Dashboard.Settings.Services.StripePaymentService;

public class StripePaymentService(
    OrganizationRepository organizationRepository,
    AuditLogPublicRepository auditLogPublicRepository,
    ILogger<StripePaymentService> logger)
{
    private const string FreePlanName = "Free";

    static StripePaymentService()
    {
        StripeConfiguration.ApiKey = ServiceSettings.Instance.StripeSecretKey;
    }

    /// <summary>
    /// Creates a subscription with payment intent for Payment Element
    /// </summary>
    public async Task<CreateSubscriptionResponse> CreateSubscriptionAsync(string userEmail, string organizationId,
        string priceId)
    {
        var customerService = new CustomerService();
        var customer = await customerService.CreateAsync(new CustomerCreateOptions
        {
            Email = userEmail,
            Metadata = new Dictionary<string, string> { { "organization_id", organizationId } }
        });

        var subscriptionService = new SubscriptionService();
        var subscription = await subscriptionService.CreateAsync(new SubscriptionCreateOptions
        {
            Customer = customer.Id,
            Items = [new SubscriptionItemOptions { Price = priceId }],
            PaymentBehavior = "default_incomplete",
            CollectionMethod = "charge_automatically",
            PaymentSettings = new SubscriptionPaymentSettingsOptions
            {
                SaveDefaultPaymentMethod = "on_subscription",
            },
            Expand = ["latest_invoice.confirmation_secret"]
        });

        return new CreateSubscriptionResponse
        {
            ClientSecret = subscription.LatestInvoice.ConfirmationSecret.ClientSecret,
            SubscriptionId = subscription.Id,
            CustomerId = customer.Id
        };
    }

    /// <summary>
    /// Changes subscription plan - takes effect at end of current billing period
    /// </summary>
    public async Task ChangeSubscriptionPlanAsync(string subscriptionId, string newPriceId)
    {
        var subscriptionService = new SubscriptionService();
        var subscription = await subscriptionService.GetAsync(subscriptionId);
        var subscriptionItemId = subscription.Items.Data[0].Id;

        await subscriptionService.UpdateAsync(subscriptionId, new SubscriptionUpdateOptions
        {
            Items =
            [
                new SubscriptionItemOptions
                {
                    Id = subscriptionItemId,
                    Price = newPriceId
                }
            ],
            ProrationBehavior = "none"
        });
    }

    /// <summary>
    /// Cancels subscription - either now or at end of billing period
    /// </summary>
    public async Task<Subscription> CancelSubscriptionAsync(string subscriptionId, bool cancelNow = false)
    {
        var subscriptionService = new SubscriptionService();

        if (cancelNow)
        {
            return await subscriptionService.CancelAsync(subscriptionId);
        }

        return await subscriptionService.UpdateAsync(subscriptionId, new SubscriptionUpdateOptions
        {
            CancelAtPeriodEnd = true
        });
    }

    /// <summary>
    /// Reactivates a canceled subscription (removes cancel_at_period_end flag)
    /// </summary>
    public async Task<Subscription> ReactivateSubscriptionAsync(string subscriptionId)
    {
        var subscriptionService = new SubscriptionService();
        return await subscriptionService.UpdateAsync(subscriptionId, new SubscriptionUpdateOptions
        {
            CancelAtPeriodEnd = false
        });
    }

    /// <summary>
    /// Gets payment method details for display (last4, brand, etc.)
    /// </summary>
    public async Task<PaymentMethodInfo?> GetSubscriptionPaymentMethodAsync(string subscriptionId)
    {
        var subscriptionService = new SubscriptionService();
        var subscription = await subscriptionService.GetAsync(subscriptionId);

        if (subscription.DefaultPaymentMethodId == null)
            return null;

        var paymentMethodService = new PaymentMethodService();
        var paymentMethod = await paymentMethodService.GetAsync(subscription.DefaultPaymentMethodId);

        return new PaymentMethodInfo
        {
            Last4 = paymentMethod.Card.Last4,
            Brand = paymentMethod.Card.Brand,
            ExpiryMonth = paymentMethod.Card.ExpMonth,
            ExpiryYear = paymentMethod.Card.ExpYear
        };
    }

    /// <summary>
    /// Gets the client secret for an incomplete subscription to resume payment
    /// </summary>
    public async Task<string?> GetIncompleteSubscriptionClientSecretAsync(string subscriptionId)
    {
        var subscriptionService = new SubscriptionService();
        var subscription = await subscriptionService.GetAsync(subscriptionId, new SubscriptionGetOptions
        {
            Expand = ["latest_invoice.confirmation_secret"]
        });

        return subscription.Status == "incomplete"
            ? subscription.LatestInvoice?.ConfirmationSecret?.ClientSecret 
            : null;
    }

    /// <summary>
    /// Gets the last 12 invoices for a customer
    /// </summary>
    public async Task<List<InvoiceInfo>> GetRecentInvoicesAsync(string customerId)
    {
        var invoiceService = new InvoiceService();
        var invoices = await invoiceService.ListAsync(new InvoiceListOptions
        {
            Customer = customerId,
            Limit = 12,
            Expand = new List<string> { "data.lines" }
        });

        return invoices.Data.Select(invoice => new InvoiceInfo
        {
            Id = invoice.Id,
            Created = invoice.Created,
            DueDate = invoice.DueDate,
            Amount = invoice.AmountPaid / 100m,
            Status = invoice.Status,
            PlanName = invoice.Lines?.Data?.FirstOrDefault()?.Description,
            InvoicePdfUrl = invoice.InvoicePdf
        }).ToList();
    }

    /// <summary>
    /// Handles Stripe webhook events
    /// </summary>
    public async Task HandleWebhookEvent(Event stripeEvent)
    {
        switch (stripeEvent.Type)
        {
            case "customer.subscription.created":
            case "customer.subscription.deleted":
            case "customer.subscription.updated":
                if (stripeEvent.Data.Object is Subscription subscription)
                {
                    await UpdateOrganizationSubscription(subscription);
                }

                break;

            case "invoice.payment_action_required":
                if (stripeEvent.Data.Object is Invoice actionRequiredInvoice)
                {
                    await HandlePaymentActionRequired(actionRequiredInvoice);
                }

                break;

            case "invoice.marked_uncollectible":
                if (stripeEvent.Data.Object is Invoice uncollectibleInvoice)
                {
                    await HandleInvoiceMarkedUncollectible(uncollectibleInvoice);
                }

                break;

            case "charge.dispute.created":
                if (stripeEvent.Data.Object is Dispute dispute)
                {
                    await HandleDisputeCreated(dispute);
                }

                break;
        }
    }

    /// <summary>
    /// Updates organization subscription based on Stripe subscription data
    /// </summary>
    private async Task UpdateOrganizationSubscription(Subscription subscription)
    {
        var organizations = await organizationRepository.FindAsync(o =>
            o.Plan != null && o.Plan.StripeCustomerId == subscription.CustomerId);
        var organization = organizations.FirstOrDefault();

        if (organization == null)
            return;

        organization.Plan ??= new Data.Entities.Organization.Plan();

        if (subscription.Status.IsTerminated())
        {
            ResetToFreePlan(organization);
        }
        else
        {
            var stripePriceId = subscription.Items.First().Price.Id;
            var plan = Plans.GetPlanByStripePriceId(stripePriceId);
            var planName = plan?.Name ?? throw new ArgumentNullException();

            organization.Plan.StripeSubscriptionId = subscription.Id;
            organization.Plan.SubscriptionPlan = planName;
            organization.Plan.SubscriptionStatus = subscription.Status;
            organization.Plan.SubscriptionCurrentPeriodStart = subscription.Items.First().CurrentPeriodStart;
            organization.Plan.SubscriptionCurrentPeriodEnd = subscription.Items.First().CurrentPeriodEnd;
            organization.Plan.SubscriptionCancelAtPeriodEnd = subscription.CancelAtPeriodEnd;
            organization.Plan.BillingInterval = stripePriceId == ServiceSettings.Instance.StripeProAnnualPriceId ? "year" : "month";

            if (subscription.Status == "active")
            {
                organization.SubscriptionSettings = plan.ToSubscriptionSettings();
            }
        }

        organization.UpdatedAt = DateTime.UtcNow;
        await organizationRepository.UpdateAsync(organization);
    }

    private async Task HandlePaymentActionRequired(Invoice invoice)
    {
        var organization = await FindOrganizationByCustomerId(invoice.CustomerId);
        if (organization == null)
        {
            logger.LogError("No organization found for Stripe customer {CustomerId} on payment_action_required", invoice.CustomerId);
            return;
        }

        await auditLogPublicRepository.CreateAsync(new AuditLog
        {
            OrgId = organization.Id,
            UserId = "Stripe",
            UserName = "Stripe",
            Category = AuditLogCategory.Billing,
            Action = "Payment Action Required",
            AdditionalInfo = $"Invoice {invoice.Id}"
        });
    }

    private async Task HandleInvoiceMarkedUncollectible(Invoice invoice)
    {
        var organization = await FindOrganizationByCustomerId(invoice.CustomerId);
        if (organization == null)
        {
            logger.LogError("No organization found for Stripe customer {CustomerId} on invoice.marked_uncollectible", invoice.CustomerId);
            return;
        }

        ResetToFreePlan(organization);
        organization.UpdatedAt = DateTime.UtcNow;
        await organizationRepository.UpdateAsync(organization);

        await auditLogPublicRepository.CreateAsync(new AuditLog
        {
            OrgId = organization.Id,
            UserId = "Stripe",
            UserName = "Stripe",
            Category = AuditLogCategory.Billing,
            Action = "Invoice Marked Uncollectible",
            AdditionalInfo = $"Invoice {invoice.Id} — reset to Free plan"
        });
    }

    private async Task HandleDisputeCreated(Dispute dispute)
    {
        var chargeService = new ChargeService();
        var charge = await chargeService.GetAsync(dispute.ChargeId);

        var organization = await FindOrganizationByCustomerId(charge.CustomerId);
        if (organization == null)
        {
            logger.LogError("No organization found for Stripe customer {CustomerId} on dispute {DisputeId}",
                charge.CustomerId, dispute.Id);
            return;
        }

        await auditLogPublicRepository.CreateAsync(new AuditLog
        {
            OrgId = organization.Id,
            UserId = "Stripe",
            UserName = "Stripe",
            Category = AuditLogCategory.Billing,
            Action = "Dispute Opened",
            AdditionalInfo = $"Charge {charge.Id}, amount {dispute.Amount / 100m:C}"
        });
    }

    private void ResetToFreePlan(Data.Entities.Organization.Organization organization)
    {
        organization.Plan ??= new Data.Entities.Organization.Plan();
        organization.Plan.StripeSubscriptionId = null;
        organization.Plan.SubscriptionPlan = FreePlanName;
        organization.Plan.SubscriptionStatus = "active";
        organization.Plan.SubscriptionCurrentPeriodStart = null;
        organization.Plan.SubscriptionCurrentPeriodEnd = null;
        organization.Plan.SubscriptionCancelAtPeriodEnd = false;
        organization.SubscriptionSettings = Plans.GetDefaultSubscriptionSettings();
    }

    private async Task<Data.Entities.Organization.Organization?> FindOrganizationByCustomerId(string? customerId)
    {
        if (string.IsNullOrEmpty(customerId))
            return null;

        var organizations = await organizationRepository.FindAsync(o =>
            o.Plan != null && o.Plan.StripeCustomerId == customerId);
        return organizations.FirstOrDefault();
    }
}