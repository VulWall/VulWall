namespace VulWall.Dashboard.Common.Services.AIServices;

/// <summary>
/// The JSON Schema a request asks the output to match.
/// </summary>
public sealed record AiJsonSchema(string Name, string Description, string Schema);

/// <summary>
/// One generation: a system prompt, one user message and the output limit. <see cref="Schema"/> and
/// <see cref="WantWebSearch"/> may be set only when the provider's <see cref="AiCapabilities"/> allow them.
/// </summary>
public sealed record AiRequest(
    string SystemPrompt,
    string UserPrompt,
    int MaxOutputTokens,
    AiJsonSchema? Schema = null,
    bool WantWebSearch = false);

public enum AiOutcome
{
    Ok,
    /// <summary>The model or a safety classifier declined.</summary>
    Refused,
    /// <summary>The output limit was hit.</summary>
    Truncated,
    /// <summary>The call succeeded but returned no usable text.</summary>
    NoOutput,
}

/// <summary>
/// The output of a generation. <see cref="Text"/> is empty unless <see cref="Outcome"/> is
/// <see cref="AiOutcome.Ok"/>. Transport and API failures are exceptions, not results.
/// </summary>
public sealed record AiResult(
    AiOutcome Outcome,
    string Text,
    string Model,
    long InputTokens,
    long OutputTokens,
    int WebSearches = 0,
    string? RefusalCategory = null);

/// <summary>The optional features a provider supports.</summary>
public sealed record AiCapabilities(bool WebSearch, bool StrictSchema);

/// <summary>
/// Selects and authenticates a provider. An empty <see cref="Model"/> or <see cref="BaseUrl"/>
/// means the provider's default. AI settings are install-wide.
/// </summary>
public sealed record AiConfig(string Provider, string ApiKey, string Model, string BaseUrl)
{
    public const string Anthropic = "anthropic";

    public bool IsEnabled => !string.IsNullOrWhiteSpace(ApiKey);
}

/// <summary>A provider adapter. Built by <see cref="AiService"/> from the current <see cref="AiConfig"/>.</summary>
public interface IAiProvider
{
    AiCapabilities Capabilities { get; }
    string Model { get; }
    Task<AiResult> GenerateAsync(AiRequest request, CancellationToken cancellationToken = default);
}

/// <summary>
/// The current AI configuration. It is read on every call, so a source backed by stored settings
/// takes effect without a restart.
/// </summary>
public interface IAiConfigSource
{
    Task<AiConfig> GetAsync(CancellationToken cancellationToken = default);
}

/// <summary>What callers use to run a generation with the configured provider.</summary>
public interface IAiService
{
    /// <exception cref="InvalidOperationException">AI is not configured, or the provider is unknown.</exception>
    Task<AiResult> GenerateAsync(AiRequest request, CancellationToken cancellationToken = default);
}
