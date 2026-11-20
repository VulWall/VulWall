using VulWall.Dashboard.Attributes;

namespace VulWall.Dashboard.Common.Utils;

public class ServiceSettings : EnvLoader
{
    private static readonly Lazy<ServiceSettings> ServiceInstance = new(() => new ServiceSettings());
    public static ServiceSettings Instance => ServiceInstance.Value;

    [Env(Name = "PORT", Default = "8081")]
    public int Port;

    [Env(Name = "AUTH0_DOMAIN", Required = true)]
    public string Auth0Domain;

    [Env(Name = "AUTH0_MANAGEMENT_DOMAIN", Required = true)]
    public string Auth0ManagementDomain;

    [Env(Name = "AUTH0_CLIENTID", Required = true)]
    public string Auth0ClientId;

    [Env(Name = "AUTH0_CLIENTSECRET", Required = true)]
    public string Auth0ClientSecret;

    [Env(Name = "MONGO_URI", Default = "mongodb://localhost:27017/VulWall-Dev")]
    public string Mongo_URI;

    [Env(Name = "STRIPE_PRO_PRICEID", Required = true)]
    public string StripeProPriceId;

    [Env(Name = "STRIPE_PRO_ANNUAL_PRICEID", Required = true)]
    public string StripeProAnnualPriceId;

    [Env(Name = "STRIPE_PUBLISHABLEKEY", Required = true)]
    public string StripePublishableKey;

    [Env(Name = "STRIPE_SECRETKEY", Required = true)]
    public string StripeSecretKey;

    [Env(Name = "STRIPE_WEBHOOKSECRET", Required = true)]
    public string StripeWebhookSecret;

    [Env(Name = "ANTHROPIC_API_KEY", Required = false)]
    public string AnthropicApiKey = string.Empty;

    [Env(Name = "DEFAULT_AI_MODEL", Default = "claude-sonnet-4-6")]
    public string DefaultAIModel = string.Empty;

    [Env(Name = "NIGHTWATCH_BASE_URL", Required = false)]
    public string NightWatchBaseUrl = string.Empty;

    [Env(Name = "NIGHTWATCH_API_KEY", Required = false)]
    public string NightWatchApiKey = string.Empty;

    [Env(Name = "RESEND_API_KEY", Required = false)]
    public string ResendApiKey = string.Empty;

    [Env(Name = "RESEND_FROM_EMAIL", Default = "VulWall <noreply@example.com>")]
    public string ResendFromEmail = string.Empty;

    [Env(Name = "NIGHTWATCH_WEBHOOK_SECRET", Required = false)]
    public string NightWatchWebhookSecret = string.Empty;

    [Env(Name = "RESEND_SCAN_COMPLETE_TEMPLATE", Required = false)]
    public string ResendScanCompleteTemplate = string.Empty;

    [Env(Name = "RESEND_DELETE_ACCOUNT_TEMPLATE_ID", Required = false)]
    public string ResendDeleteAccountTemplateId = string.Empty;

    [Env(Name = "RESEND_CLAIM_NOTIFICATION_TEMPLATE_ID", Required = false)]
    public string ResendClaimNotificationTemplateId = string.Empty;

    [Env(Name = "SENTRY_DSN")]
    public string? SentryDsn;
}
