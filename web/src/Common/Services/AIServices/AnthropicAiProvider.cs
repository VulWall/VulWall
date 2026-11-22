using Anthropic;
using Anthropic.Core;
using Anthropic.Models.Messages;

namespace VulWall.Dashboard.Common.Services.AIServices;

/// <summary>
/// <see cref="IAiProvider"/> for Anthropic's Messages API. Text output only: the web app sends no
/// schema and no web search, so neither is implemented here.
/// </summary>
public sealed class AnthropicAiProvider(AnthropicClient client, string model, ILogger<AnthropicAiProvider> logger)
    : IAiProvider
{
    public const string DefaultModel = "claude-sonnet-5-5";

    // Models that take output_config.effort. Matched by prefix; others get no effort, which every
    // model accepts. Keep in step with the scanner's internal/ai/anthropic list.
    private static readonly string[] EffortModels =
    [
        "claude-fable-", "claude-mythos-", "claude-opus-5", "claude-opus-4-8", "claude-opus-4-7",
        "claude-opus-4-6", "claude-opus-4-5", "claude-sonnet-5", "claude-sonnet-4-6", "claude-haiku-5",
    ];

    /// <summary>
    /// A client for the given key only. With an explicit key the SDK reads no credential from the
    /// environment or from a profile on disk.
    /// </summary>
    public static AnthropicClient CreateClient(AiConfig config, HttpClient? httpClient = null)
    {
        if (!config.IsEnabled)
            throw new InvalidOperationException("No AI API key configured");
        var options = new ClientOptions { ApiKey = config.ApiKey };
        if (!string.IsNullOrWhiteSpace(config.BaseUrl))
            options.BaseUrl = config.BaseUrl;
        if (httpClient is not null)
            options.HttpClient = httpClient;
        return new AnthropicClient(options);
    }

    public static bool AcceptsEffort(string model) =>
        EffortModels.Any(p => model.StartsWith(p, StringComparison.Ordinal) ||
                              model.StartsWith("anthropic." + p, StringComparison.Ordinal));

    public AiCapabilities Capabilities { get; } = new(WebSearch: false, StrictSchema: false);

    public string Model => model;

    public async Task<AiResult> GenerateAsync(AiRequest request, CancellationToken cancellationToken = default)
    {
        var parameters = new MessageCreateParams
        {
            Model = model,
            // Thinking counts against this limit on current models.
            MaxTokens = request.MaxOutputTokens,
            System = request.SystemPrompt,
            Messages = [new UserMessageParam { Content = request.UserPrompt }],
        };
        if (AcceptsEffort(model))
            parameters = parameters with { OutputConfig = new OutputConfig { Effort = Effort.Low } };

        var message = await client.Messages.Create(parameters, cancellationToken: cancellationToken);
        var usedModel = message.Model.Raw() ?? model;
        var inTokens = message.Usage.InputTokens;
        var outTokens = message.Usage.OutputTokens;

        // Check the stop reason before reading content: a refusal can come with partial text, and
        // a truncated answer is not a summary.
        var stopReason = message.StopReason?.Raw();
        if (stopReason == "refusal")
        {
            var category = message.StopDetails?.Category?.Raw();
            logger.LogWarning("AI request refused by {Model} (category {Category})", usedModel, category);
            return new AiResult(AiOutcome.Refused, string.Empty, usedModel, inTokens, outTokens, RefusalCategory: category);
        }
        if (stopReason is "max_tokens" or "model_context_window_exceeded")
            return new AiResult(AiOutcome.Truncated, string.Empty, usedModel, inTokens, outTokens);

        // Read text blocks by type: thinking blocks come first on current models.
        var text = string.Concat(message.Content
            .Select(b => b.TryPickText(out var t) ? t.Text : null)
            .Where(t => t is not null)).Trim();
        return new AiResult(text.Length > 0 ? AiOutcome.Ok : AiOutcome.NoOutput, text, usedModel, inTokens, outTokens);
    }
}
