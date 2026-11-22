using System.Net;
using System.Net.Sockets;
using System.Text;

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

    public bool HasApiKey => !string.IsNullOrWhiteSpace(ApiKey);

    public bool IsKnownProvider => Provider == Anthropic;

    /// <summary>Why the settings cannot be used although a key is set, or null.</summary>
    public string? Problem => !IsKnownProvider
        ? $"unknown AI_PROVIDER '{Provider}' (supported: {Anthropic})"
        : ValidateBaseUrl(BaseUrl);

    /// <summary>A key is set and the rest of the settings are usable.</summary>
    public bool IsEnabled => HasApiKey && Problem is null;

    /// <summary>
    /// Accepts an empty value (the provider's own API), an https URL, or an http URL whose host is
    /// local: loopback, a private or link-local address, localhost, a .local/.internal/.localhost name
    /// or a single-label name such as a compose service. Plain http to anything else would send the
    /// key and the prompts across the internet unencrypted. Same rule as the scanner's
    /// ai.ValidateBaseURL. Returns the problem, or null.
    /// </summary>
    public static string? ValidateBaseUrl(string baseUrl)
    {
        if (string.IsNullOrEmpty(baseUrl))
            return null;
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri) || string.IsNullOrEmpty(uri.Host))
            return $"AI_BASE_URL '{baseUrl}' is not an absolute URL";
        if (!string.IsNullOrEmpty(uri.UserInfo))
            return "AI_BASE_URL must not contain credentials";
        return uri.Scheme switch
        {
            "https" => null,
            "http" when IsLocalHost(uri.Host) => null,
            "http" => $"AI_BASE_URL '{baseUrl}' uses http to a non-local host; use https",
            _ => $"AI_BASE_URL '{baseUrl}' must use https (or http to a local host)",
        };
    }

    private static bool IsLocalHost(string host)
    {
        if (IPAddress.TryParse(host.Trim('[', ']'), out var ip))
        {
            if (IPAddress.IsLoopback(ip))
                return true;
            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
                return ip.IsIPv6LinkLocal || ip.IsIPv6UniqueLocal;
            var b = ip.GetAddressBytes();
            return b[0] == 10 || (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168) ||
                   (b[0] == 169 && b[1] == 254);
        }
        host = host.TrimEnd('.').ToLowerInvariant();
        return host == "localhost" || !host.Contains('.') || host.EndsWith(".localhost") ||
               host.EndsWith(".local") || host.EndsWith(".internal");
    }

    // The key never goes into logs or exception messages through ToString().
    private bool PrintMembers(StringBuilder builder)
    {
        builder.Append($"Provider = {Provider}, ApiKey = {(HasApiKey ? "***" : "")}, Model = {Model}, BaseUrl = {BaseUrl}");
        return true;
    }
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
