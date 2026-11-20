using Anthropic;
using Anthropic.Models.Messages;
using VulWall.Dashboard.Common.Utils;

namespace VulWall.Dashboard.Common.Services.AIServices;

public class AnthropicAIService : IAIService
{
    private readonly ILogger<AnthropicAIService> _logger;
    private readonly PromptLoader _promptLoader;
    private readonly AnthropicClient? _client;

    private const int DefaultMaxTokens = 1024;
    private const double DefaultTemperature = 0.7;

    public AnthropicAIService(
        ILogger<AnthropicAIService> logger,
        PromptLoader promptLoader,
        AnthropicClient? client = null)
    {
        _logger = logger;
        _promptLoader = promptLoader;
        _client = client;
    }

    public async Task<string?> GetResponseAsync(
        string promptName,
        string userMessage,
        string? model = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            if (_client is null)
            {
                _logger.LogWarning("Anthropic API key is not configured");
                return null;
            }

            var systemPrompt = await _promptLoader.LoadPromptFromFileAsync(promptName);
            var selectedModel = model ?? ServiceSettings.Instance.DefaultAIModel;

            var parameters = new MessageCreateParams
            {
                Model = selectedModel,
                MaxTokens = DefaultMaxTokens,
                Temperature = DefaultTemperature,
                System = systemPrompt,
                Messages =
                [
                    new MessageParam
                    {
                        Role = Role.User,
                        Content = userMessage,
                    }
                ],
            };

            var message = await _client.Messages.Create(
                parameters,
                cancellationToken: cancellationToken);

            var response = ExtractTextResponse(message);

            if (string.IsNullOrEmpty(response))
            {
                _logger.LogWarning(
                    "No response received from Anthropic API for prompt: {PromptName}",
                    promptName);
                return null;
            }

            return response;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting AI response for prompt: {PromptName}", promptName);
            throw;
        }
    }

    /// <summary>
    /// Extracts the text content from an Anthropic message response.
    /// Concatenates all text blocks if the response contains multiple content blocks.
    /// </summary>
    private static string ExtractTextResponse(Message message)
    {
        if (message.Content is null || message.Content.Count == 0)
            return string.Empty;

        var textParts = new List<string>();

        foreach (var block in message.Content)
        {
            if (block.TryPickText(out var textBlock))
            {
                textParts.Add(textBlock.Text);
            }
            else if (block.TryPickToolUse(out var toolUseBlock))
            {
                // If the response contains a tool_use block (structured output),
                // return the tool input as serialized JSON.
                return toolUseBlock.Input.ToString() ?? string.Empty;
            }
        }

        return string.Join("", textParts);
    }
}
