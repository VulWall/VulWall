using Anthropic;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using MongoDB.Driver;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Razor;
using VulWall.Dashboard.Common.Services.AIServices;
using VulWall.Dashboard.Account.Services;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Extensions.Configuration;
using VulWall.Dashboard.Settings.Services;
using VulWall.Dashboard.Assets.Services;
using VulWall.Dashboard.Reports.Services.ReportGeneration;
using VulWall.Dashboard.Reports.Services;
using VulWall.Dashboard.Reports.Services.SharedLinkService;
using VulWall.Dashboard.Scans.Services;
using VulWall.Dashboard.Recommendations.Services;
using VulWall.Dashboard.Dashboard.Services;
using VulWall.Dashboard.Discoveries.Services;
using VulWall.Dashboard.Common.Services.ScanTrigger;
using VulWall.Dashboard.Reports.Services.ExecutiveSummaryJob;
using VulWall.Dashboard.Common.Services.RateLimiter;
using VulWall.Dashboard.Common.Services;

namespace VulWall.Dashboard.Extensions;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCommonServices(this IServiceCollection services)
    {
        services.AddControllersWithViews(options =>
        {
            options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
        })
        .AddJsonOptions(options =>
        {
            options.JsonSerializerOptions.PropertyNamingPolicy = System.Text.Json.JsonNamingPolicy.CamelCase;
            options.JsonSerializerOptions.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter());
        });

        services.AddHealthChecks();
        services.AddHttpContextAccessor();
        services.AddMemoryCache();
        services.AddAntiforgeryConfiguration();
        services.AddCustomViewLocationExpander();
        services.AddLocalAuthentication();
        services.AddOrganizationServices();
        services.AddAiServices();
        services.AddScanTriggerServices();
        services.AddSingleton<IpRateLimiterService>();
        services.AddSingleton<KnowledgeBaseCacheService>();

        return services;
    }

    public static IServiceCollection AddVerticalServices(this IServiceCollection services)
    {
        services.AddAssetServices();
        services.AddSettingsServices();
        services.AddReportServices();
        services.AddScansServices();
        services.AddRecommendationsServices();
        services.AddDashboardServices();
        services.AddDiscoveriesServices();

        return services;
    }

    public static IServiceCollection AddMongoServices(this IServiceCollection services)
    {
        MongoDbConfiguration.ConfigureSerialization();
        MongoDbConfiguration.ConfigureClient(services);
        MongoDbConfiguration.RegisterRepositories(services);
        services.AddMongoDataProtection();

        return services;
    }

    private static IServiceCollection AddMongoDataProtection(this IServiceCollection services)
    {
        services.AddDataProtection()
            .SetApplicationName("VulWall.Dashboard")
            .PersistKeysToMongoDb(sp => sp.GetRequiredService<IMongoDatabase>());

        return services;
    }

    private static IServiceCollection AddOrganizationServices(this IServiceCollection services)
    {
        services.AddScoped<IOrganizationContext, OrganizationContext>();
        services.AddSingleton<IFeatureAccessService>(
            new FullFeatureAccessService(ServiceSettings.Instance.SharedLinksEnabled));

        return services;
    }

    private static IServiceCollection AddAntiforgeryConfiguration(this IServiceCollection services)
    {
        // The app itself only listens on HTTP; with SECURE_COOKIES=true TLS is terminated by a
        // proxy on the standard port, so plain-HTTP requests are redirected to 443.
        services.AddHttpsRedirection(options => options.HttpsPort = 443);

        services.AddAntiforgery(options =>
        {
            options.SuppressXFrameOptionsHeader = false;
            options.Cookie.SecurePolicy = CookieSecurePolicyFromSettings();
        });

        return services;
    }

    /// <summary>
    /// SECURE_COOKIES=true forces the Secure flag. Otherwise the flag follows the request scheme,
    /// so a plain-HTTP install still works and an HTTPS request still gets a Secure cookie.
    /// </summary>
    internal static CookieSecurePolicy CookieSecurePolicyFromSettings() =>
        ServiceSettings.Instance.SecureCookies ? CookieSecurePolicy.Always : CookieSecurePolicy.SameAsRequest;

    private static IServiceCollection AddCustomViewLocationExpander(this IServiceCollection services)
    {
        services.Configure<RazorViewEngineOptions>(options =>
        {
            options.ViewLocationExpanders.Add(new VerticalViewLocationExpander());
        });

        return services;
    }

    /// <summary>
    /// Local cookie authentication against the single admin in the users collection.
    /// A hosted fork that needs SSO would register an OIDC handler here instead (cookie scheme
    /// as the sign-in scheme, OpenIdConnect as the challenge scheme) and replace AccountController.
    /// </summary>
    private static IServiceCollection AddLocalAuthentication(this IServiceCollection services)
    {
        services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
            .AddCookie(options =>
            {
                options.LoginPath = "/login";
                options.LogoutPath = "/logout";
                options.AccessDeniedPath = "/login";
                options.ExpireTimeSpan = TimeSpan.FromHours(12);
                options.SlidingExpiration = true;
                options.Cookie.Name = "vulwall.auth";
                options.Cookie.HttpOnly = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = CookieSecurePolicyFromSettings();
            });

        services.AddScoped<AccountService>();

        return services;
    }

    private static IServiceCollection AddAssetServices(this IServiceCollection services)
    {
        services.AddScoped<AssetsService>();

        return services;
    }

    private static IServiceCollection AddSettingsServices(this IServiceCollection services)
    {
        services.AddScoped<SettingsService>();

        return services;
    }

    private static IServiceCollection AddReportServices(this IServiceCollection services)
    {
        services.AddScoped<VulnerabilitySummaryBuilder>();
        services.AddScoped<FindingsAggregator>();
        services.AddScoped<ExecutiveSummaryService>();
        services.AddScoped<ScoreHistoryBuilder>();
        services.AddScoped<FindingDeltaBuilder>();
        services.AddScoped<SummaryReportBuilder>();
        services.AddScoped<TechnicalReportBuilder>();
        services.AddScoped<ReportsService>();
        services.AddScoped<SharedLinkService>();
        services.AddScoped<ExecutiveSummaryProcessor>();
        services.AddHostedService<ExecutiveSummaryPoller>();

        return services;
    }

    private static IServiceCollection AddScansServices(this IServiceCollection services)
    {
        services.AddScoped<ScansService>();

        return services;
    }

    private static IServiceCollection AddRecommendationsServices(this IServiceCollection services)
    {
        // Register the concrete service and expose it through the Common-layer read interface
        // so Dashboard, Reports, and other verticals can depend on ISuppressionFilter without
        // taking a direct reference to a Recommendations-internal type.
        services.AddScoped<FindingSuppressionService>();
        services.AddScoped<ISuppressionFilter>(sp => sp.GetRequiredService<FindingSuppressionService>());
        services.AddScoped<RecommendationsService>();

        return services;
    }

    private static IServiceCollection AddAiServices(this IServiceCollection services)
    {
        services.AddSingleton<PromptLoader>();
        var apiKey = ServiceSettings.Instance.AnthropicApiKey;
        if (!string.IsNullOrEmpty(apiKey))
            services.AddSingleton(new AnthropicClient { ApiKey = apiKey });
        services.AddScoped<IAIService, AnthropicAIService>();

        return services;
    }

    private static IServiceCollection AddScanTriggerServices(this IServiceCollection services)
    {
        services.AddScoped<ScanTriggerService>();
        return services;
    }

    private static IServiceCollection AddDashboardServices(this IServiceCollection services)
    {
        services.AddScoped<SecurityScoreService>();
        services.AddScoped<ISecurityScoreProvider>(sp => sp.GetRequiredService<SecurityScoreService>());
        services.AddScoped<DashboardService>();

        return services;
    }

    private static IServiceCollection AddDiscoveriesServices(this IServiceCollection services)
    {
        services.AddScoped<DiscoveriesService>();

        return services;
    }
}
