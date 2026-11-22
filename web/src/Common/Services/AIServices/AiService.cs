using Anthropic;
using VulWall.Dashboard.Common.Utils;

namespace VulWall.Dashboard.Common.Services.AIServices;

/// <summary>
/// Reads <see cref="ServiceSettings"/> (AI_PROVIDER, AI_API_KEY, AI_MODEL, AI_BASE_URL). Empty values
/// count as unset.
/// </summary>
public sealed class EnvAiConfigSource : IAiConfigSource
{
    public Task<AiConfig> GetAsync(CancellationToken cancellationToken = default)
    {
        var s = ServiceSettings.Instance;
        var provider = string.IsNullOrWhiteSpace(s.AiProvider) ? AiConfig.Anthropic : s.AiProvider.Trim().ToLowerInvariant();
        return Task.FromResult(new AiConfig(provider, s.AiApiKey.Trim(), s.AiModel.Trim(), s.AiBaseUrl.Trim()));
    }
}

/// <summary>
/// Whether AI features are on. The executive summary poller and the "how to get AI guidance" hints ask
/// it each time instead of reading the configuration once at start-up. An unknown provider counts as
/// off, so finished scans are marked skipped (and summarized once it is fixed) instead of failing.
/// </summary>
public sealed class AiStatus(IAiConfigSource configSource, ILogger<AiStatus> logger)
{
    private string? _reportedProvider;

    public async Task<bool> IsEnabledAsync(CancellationToken cancellationToken = default)
    {
        var config = await configSource.GetAsync(cancellationToken);
        if (config.HasApiKey && !config.IsKnownProvider && config.Provider != Volatile.Read(ref _reportedProvider))
        {
            Volatile.Write(ref _reportedProvider, config.Provider);
            logger.LogError("AI is disabled: unknown AI_PROVIDER '{Provider}' (supported: {Supported})",
                config.Provider, AiConfig.Anthropic);
        }
        return config.IsEnabled;
    }
}

/// <summary>
/// Runs generations with the provider the current configuration selects, and keeps that provider
/// until the configuration changes.
/// </summary>
public sealed class AiService(IAiConfigSource configSource, ILoggerFactory loggerFactory) : IAiService
{
    private readonly Lock _lock = new();
    private AiConfig? _config;
    private IAiProvider? _provider;

    public async Task<AiResult> GenerateAsync(AiRequest request, CancellationToken cancellationToken = default)
    {
        var provider = GetProvider(await configSource.GetAsync(cancellationToken));
        var capabilities = provider.Capabilities;
        if (request.Schema is not null && !capabilities.StrictSchema)
            throw new NotSupportedException($"Provider model {provider.Model} does not support schema output");
        if (request.WantWebSearch && !capabilities.WebSearch)
            throw new NotSupportedException($"Provider model {provider.Model} does not support web search");
        return await provider.GenerateAsync(request, cancellationToken);
    }

    private IAiProvider GetProvider(AiConfig config)
    {
        if (!config.HasApiKey)
            throw new InvalidOperationException("AI is not configured (AI_API_KEY is empty)");

        lock (_lock)
        {
            if (_provider is not null && config == _config)
                return _provider;
            _provider = Create(config);
            _config = config;
            return _provider;
        }
    }

    private IAiProvider Create(AiConfig config) => config.Provider switch
    {
        AiConfig.Anthropic => new AnthropicAiProvider(
            AnthropicAiProvider.CreateClient(config),
            string.IsNullOrEmpty(config.Model) ? AnthropicAiProvider.DefaultModel : config.Model,
            loggerFactory.CreateLogger<AnthropicAiProvider>()),
        _ => throw new InvalidOperationException(
            $"Unknown AI_PROVIDER '{config.Provider}' (supported: {AiConfig.Anthropic})"),
    };
}
