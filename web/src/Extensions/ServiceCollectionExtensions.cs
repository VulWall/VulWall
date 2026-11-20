using Anthropic;
using Auth0.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using MongoDB.Driver;
using DnsClient;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Razor;
using VulWall.Dashboard.Common.Services.AIServices;
using VulWall.Dashboard.Common.Services.Auth0;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Extensions.Configuration;
using VulWall.Dashboard.Settings.Services;
using VulWall.Dashboard.Assets.Services;
using VulWall.Dashboard.Assets.Services.DomainVerifier;
using VulWall.Dashboard.Reports.Services.ReportGeneration;
using VulWall.Dashboard.Reports.Services;
using VulWall.Dashboard.Reports.Services.SharedLinkService;
using VulWall.Dashboard.Scans.Services;
using VulWall.Dashboard.Recommendations.Services;
using VulWall.Dashboard.Dashboard.Services;
using VulWall.Dashboard.Discoveries.Services;
using VulWall.Dashboard.Common.Services.NightWatch;
using VulWall.Dashboard.Common.Services.Email;
using VulWall.Dashboard.Webhooks.Services;
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
        services.AddSessionSupport();
        services.AddAntiforgeryConfiguration();
        services.AddCustomViewLocationExpander();
        services.AddAuth0Authentication();
        services.AddOrganizationServices();
        services.AddAiServices();
        services.AddNightWatchServices();
        services.AddEmailServices();
        services.AddSingleton<IpRateLimiterService>();
        services.AddSingleton<KnowledgeBaseCacheService>();
        services.AddExceptionHandler<Middleware.AuthFailureExceptionHandler>();

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
        services.AddWebhooksServices();

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
        services.AddScoped<IOrganizationSyncService, OrganizationSyncService>();
        services.AddHttpClient(Auth0ManagementService.TokenHttpClientName);
        services.AddHttpClient(Auth0ManagementService.ManagementHttpClientName);
        services.AddSingleton<IAuth0ManagementService, Auth0ManagementService>();
        services.AddSingleton<IFeatureAccessService, FullFeatureAccessService>();

        return services;
    }

    private static IServiceCollection AddSessionSupport(this IServiceCollection services)
    {
        services.AddSession(options =>
        {
            options.IdleTimeout = TimeSpan.FromHours(24);
            options.Cookie.HttpOnly = true;
            options.Cookie.IsEssential = true;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            options.Cookie.SameSite = SameSiteMode.Lax;
        });

        return services;
    }

    private static IServiceCollection AddAntiforgeryConfiguration(this IServiceCollection services)
    {
        services.AddAntiforgery(options => { options.SuppressXFrameOptionsHeader = false; });

        return services;
    }

    private static IServiceCollection AddCustomViewLocationExpander(this IServiceCollection services)
    {
        services.Configure<RazorViewEngineOptions>(options =>
        {
            options.ViewLocationExpanders.Add(new VerticalViewLocationExpander());
        });

        return services;
    }

    private static IServiceCollection AddAuth0Authentication(this IServiceCollection services)
    {
        var auth0Domain = ServiceSettings.Instance.Auth0Domain;
        var auth0ClientId = ServiceSettings.Instance.Auth0ClientId;
        var auth0ClientSecret = ServiceSettings.Instance.Auth0ClientSecret;

        services.AddAuth0WebAppAuthentication(options =>
        {
            options.Domain = auth0Domain;
            options.ClientId = auth0ClientId;
            options.ClientSecret = auth0ClientSecret;
            options.Scope = "openid profile email";
        });

        // Register as IPostConfigureOptions to run AFTER Auth0 SDK's own IPostConfigureOptions,
        // which overwrites any events set via options.OpenIdConnectEvents or services.PostConfigure.
        services.AddSingleton<IPostConfigureOptions<OpenIdConnectOptions>, Auth0EventConfiguration>();

        return services;
    }

    private static IServiceCollection AddAssetServices(this IServiceCollection services)
    {
        // DNS lookup client for domain verification
        services.AddSingleton<ILookupClient>(_ =>
        {
            var options = new LookupClientOptions
            {
                UseCache = true,
                Timeout = TimeSpan.FromSeconds(5)
            };
            return new LookupClient(options);
        });

        services.AddScoped<IDomainVerifier, DomainVerifier>();
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

    private static IServiceCollection AddNightWatchServices(this IServiceCollection services)
    {
        services.AddHttpClient<NightWatchService>();
        return services;
    }

    private static IServiceCollection AddWebhooksServices(this IServiceCollection services)
    {
        services.AddScoped<NightWatchWebhookService>();
        return services;
    }

    private static IServiceCollection AddEmailServices(this IServiceCollection services)
    {
        services.AddSingleton<IEmailService, NullEmailService>();
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
