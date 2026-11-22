using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using VulWall.Dashboard.Common.Services.AIServices;

namespace VulWall.Dashboard.Tests.Common;

public class AnthropicAiProviderTests
{
    private sealed class CapturingHandler(string responseJson) : HttpMessageHandler
    {
        public List<(HttpRequestMessage Request, string Body)> Requests { get; } = [];

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Requests.Add((request, request.Content is null ? "" : await request.Content.ReadAsStringAsync(ct)));
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(responseJson, Encoding.UTF8, "application/json"),
            };
        }
    }

    private static string Response(string stopReason, string content, string stopDetails = "null") =>
        """{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-5-5","content":""" + content +
        ""","stop_reason":""" + JsonSerializer.Serialize(stopReason) +
        ""","stop_sequence":null,"stop_details":""" + stopDetails +
        ""","usage":{"input_tokens":120,"output_tokens":45}}""";

    private const string ThinkingThenText =
        """[{"type":"thinking","thinking":"","signature":"sig"},{"type":"text","text":" Two sentences here. And one more. "}]""";

    private static (AnthropicAiProvider Provider, CapturingHandler Handler) Create(string responseJson,
        string model = AnthropicAiProvider.DefaultModel)
    {
        var handler = new CapturingHandler(responseJson);
        var client = AnthropicAiProvider.CreateClient(
            new AiConfig(AiConfig.Anthropic, "test-key", model, "http://ai.test"), new HttpClient(handler));
        return (new AnthropicAiProvider(client, model, NullLogger<AnthropicAiProvider>.Instance), handler);
    }

    private static readonly AiRequest Request = new("system prompt", "user prompt", 4096);

    [Fact]
    public async Task Generate_SendsNoSamplingParametersAndLowEffort()
    {
        var (provider, handler) = Create(Response("end_turn", ThinkingThenText));

        await provider.GenerateAsync(Request);

        var (request, body) = Assert.Single(handler.Requests);
        Assert.Equal("http://ai.test/v1/messages", request.RequestUri!.ToString());
        // SDK 13.x sends the key as a bearer token and no x-api-key header (the docs say so).
        Assert.Equal("Bearer test-key", request.Headers.Authorization?.ToString());
        Assert.False(request.Headers.Contains("x-api-key"));
        Assert.Equal("2026-10-21", request.Headers.GetValues("anthropic-version").Single());

        var json = JsonDocument.Parse(body).RootElement;
        foreach (var removed in new[] { "temperature", "top_p", "top_k", "thinking" })
            Assert.False(json.TryGetProperty(removed, out _), $"request sends {removed}");
        Assert.Equal("claude-sonnet-5-5", json.GetProperty("model").GetString());
        Assert.Equal(4096, json.GetProperty("max_tokens").GetInt32());
        Assert.Equal("system prompt", json.GetProperty("system").GetString());
        Assert.Equal("low", json.GetProperty("output_config").GetProperty("effort").GetString());
        var message = Assert.Single(json.GetProperty("messages").EnumerateArray());
        Assert.Equal("user", message.GetProperty("role").GetString());
        Assert.Equal("user prompt", message.GetProperty("content").GetString());
    }

    [Fact]
    public async Task Generate_OlderModelGetsNoEffort()
    {
        var (provider, handler) = Create(Response("end_turn", ThinkingThenText), model: "claude-sonnet-4-5");

        await provider.GenerateAsync(Request);

        var json = JsonDocument.Parse(handler.Requests.Single().Body).RootElement;
        Assert.False(json.TryGetProperty("output_config", out _));
    }

    [Fact]
    public async Task Generate_ThinkingThenText_ReturnsText()
    {
        var (provider, _) = Create(Response("end_turn", ThinkingThenText));

        var result = await provider.GenerateAsync(Request);

        Assert.Equal(AiOutcome.Ok, result.Outcome);
        Assert.Equal("Two sentences here. And one more.", result.Text);
        Assert.Equal("claude-sonnet-5-5", result.Model);
        Assert.Equal(120, result.InputTokens);
        Assert.Equal(45, result.OutputTokens);
    }

    [Fact]
    public async Task Generate_MaxTokens_IsTruncatedEvenWithText()
    {
        var (provider, _) = Create(Response("max_tokens", ThinkingThenText));

        var result = await provider.GenerateAsync(Request);

        Assert.Equal(AiOutcome.Truncated, result.Outcome);
        Assert.Empty(result.Text);
    }

    [Fact]
    public async Task Generate_Refusal_IsRefusedWithCategory()
    {
        var (provider, handler) = Create(Response("refusal", "[]",
            """{"type":"refusal","category":"cyber","explanation":"declined"}"""));

        var result = await provider.GenerateAsync(Request);

        Assert.Equal(AiOutcome.Refused, result.Outcome);
        Assert.Equal("cyber", result.RefusalCategory);
        Assert.Empty(result.Text);
        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task Generate_OnlyThinking_IsNoOutput()
    {
        var (provider, _) = Create(Response("end_turn", """[{"type":"thinking","thinking":"","signature":"s"}]"""));

        Assert.Equal(AiOutcome.NoOutput, (await provider.GenerateAsync(Request)).Outcome);
    }

    [Fact]
    public async Task CreateClient_WithoutBaseUrl_UsesAnthropicNotAmbientBaseUrl()
    {
        var previous = Environment.GetEnvironmentVariable("ANTHROPIC_BASE_URL");
        Environment.SetEnvironmentVariable("ANTHROPIC_BASE_URL", "http://ambient.test");
        try
        {
            var handler = new CapturingHandler(Response("end_turn", ThinkingThenText));
            var client = AnthropicAiProvider.CreateClient(
                new AiConfig(AiConfig.Anthropic, "test-key", "", ""), new HttpClient(handler));
            await new AnthropicAiProvider(client, AnthropicAiProvider.DefaultModel,
                NullLogger<AnthropicAiProvider>.Instance).GenerateAsync(Request);

            Assert.Equal("https://api.anthropic.com/v1/messages", handler.Requests.Single().Request.RequestUri!.ToString());
        }
        finally
        {
            Environment.SetEnvironmentVariable("ANTHROPIC_BASE_URL", previous);
        }
    }

    [Fact]
    public void CreateClient_WithoutKey_Throws()
    {
        Assert.Throws<InvalidOperationException>(() =>
            AnthropicAiProvider.CreateClient(new AiConfig(AiConfig.Anthropic, " ", "", "")));
    }

    [Theory]
    [InlineData("claude-sonnet-5-5", true)]
    [InlineData("claude-opus-4-8", true)]
    [InlineData("anthropic.claude-sonnet-5-5", true)]
    [InlineData("claude-sonnet-4-5", false)]
    [InlineData("claude-haiku-4-5", false)]
    public void AcceptsEffort(string model, bool expected) =>
        Assert.Equal(expected, AnthropicAiProvider.AcceptsEffort(model));
}

public class AiServiceTests
{
    private sealed class Configs(AiConfig config) : IAiConfigSource
    {
        public AiConfig Config { get; set; } = config;
        public Task<AiConfig> GetAsync(CancellationToken cancellationToken = default) => Task.FromResult(Config);
    }

    [Fact]
    public async Task Generate_WithoutKey_Throws()
    {
        var service = new AiService(new Configs(new AiConfig("anthropic", "", "", "")), NullLoggerFactory.Instance);

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.GenerateAsync(new AiRequest("s", "u", 10)));
    }

    [Fact]
    public async Task Generate_UnknownProvider_Throws()
    {
        var service = new AiService(new Configs(new AiConfig("openai", "k", "", "")), NullLoggerFactory.Instance);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.GenerateAsync(new AiRequest("s", "u", 10)));
        Assert.Contains("openai", ex.Message);
    }

    [Fact]
    public async Task Generate_SchemaOnTextOnlyProvider_IsRejectedBeforeAnyCall()
    {
        // The base URL is unreachable: the check must run before a request is sent.
        var service = new AiService(new Configs(new AiConfig("anthropic", "k", "", "http://127.0.0.1:1")),
            NullLoggerFactory.Instance);

        await Assert.ThrowsAsync<NotSupportedException>(() => service.GenerateAsync(
            new AiRequest("s", "u", 10, new AiJsonSchema("n", "d", "{}"))));
        await Assert.ThrowsAsync<NotSupportedException>(() => service.GenerateAsync(
            new AiRequest("s", "u", 10, WantWebSearch: true)));
    }

    [Fact]
    public async Task AiStatus_FollowsTheCurrentConfig()
    {
        var configs = new Configs(new AiConfig("anthropic", "", "", ""));
        var status = new AiStatus(configs, NullLogger<AiStatus>.Instance);

        Assert.False(await status.IsEnabledAsync());
        configs.Config = configs.Config with { ApiKey = "k" };
        Assert.True(await status.IsEnabledAsync());
        configs.Config = configs.Config with { Provider = "openia" };
        Assert.False(await status.IsEnabledAsync());
        configs.Config = configs.Config with { Provider = "anthropic", BaseUrl = "http://gateway.example.com" };
        Assert.False(await status.IsEnabledAsync());
        configs.Config = configs.Config with { BaseUrl = "http://litellm:4000" };
        Assert.True(await status.IsEnabledAsync());
    }

    [Fact]
    public async Task Generate_PlainHttpToRemoteHost_IsRefusedBeforeAnyCall()
    {
        var service = new AiService(new Configs(new AiConfig("anthropic", "k", "", "http://gateway.example.com")),
            NullLoggerFactory.Instance);

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            service.GenerateAsync(new AiRequest("s", "u", 10)));
        Assert.Contains("https", ex.Message);
    }

    [Theory]
    [InlineData("", true)]
    [InlineData("https://gateway.example.com", true)]
    [InlineData("https://gateway.example.com/anthropic/", true)]
    [InlineData("http://localhost:4000", true)]
    [InlineData("http://127.0.0.1:4000", true)]
    [InlineData("http://[::1]:4000", true)]
    [InlineData("http://10.0.0.5", true)]
    [InlineData("http://172.20.0.3:8080", true)]
    [InlineData("http://192.168.1.10:8080", true)]
    [InlineData("http://litellm:4000", true)]
    [InlineData("http://gateway.internal", true)]
    [InlineData("http://api.anthropic.com", false)]
    [InlineData("http://8.8.8.8", false)]
    [InlineData("http://172.32.0.1", false)]
    [InlineData("ftp://gateway.example.com", false)]
    [InlineData("https://user:pass@gateway.example.com", false)]
    [InlineData("gateway.example.com", false)]
    public void ValidateBaseUrl(string url, bool ok) =>
        Assert.Equal(ok, AiConfig.ValidateBaseUrl(url) is null);

    [Fact]
    public void AiConfig_ToString_MasksTheKey()
    {
        var text = new AiConfig("anthropic", "sk-ant-secret", "m", "").ToString();

        Assert.DoesNotContain("sk-ant-secret", text);
        Assert.Contains("ApiKey = ***", text);
        Assert.Contains("Provider = anthropic", text);
    }
}
