using System.Net;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using VulWall.Dashboard.About.Models;
using VulWall.Dashboard.About.Services;

namespace VulWall.Dashboard.Tests.About;

public class UpdateCheckServiceTests
{
    private sealed class StubHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) : HttpMessageHandler
    {
        public int Calls { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Calls++;
            return Task.FromResult(respond(request));
        }
    }

    private static (UpdateCheckService Service, StubHandler Handler) Create(Func<HttpRequestMessage, HttpResponseMessage> respond)
    {
        var handler = new StubHandler(respond);
        var service = new UpdateCheckService(new HttpClient(handler), new MemoryCache(new MemoryCacheOptions()),
            NullLogger<UpdateCheckService>.Instance);
        return (service, handler);
    }

    private static HttpResponseMessage Release(string tag) => new(HttpStatusCode.OK)
    {
        Content = new StringContent($$"""{"tag_name":"{{tag}}","html_url":"https://evil.example/"}""")
    };

    [Fact]
    public async Task NewerRelease_IsAvailable_WithAReleaseUrlWeBuilt()
    {
        var (service, _) = Create(_ => Release("v1.2.0"));

        var result = await service.CheckAsync("v1.1.9");

        Assert.Equal(UpdateStatus.Available, result.Status);
        Assert.Equal("v1.2.0", result.LatestVersion);
        Assert.Equal("https://github.com/VulWall/VulWall/releases/tag/v1.2.0", result.ReleaseUrl);
    }

    [Theory]
    [InlineData("v1.2.0")]
    [InlineData("1.2.0")]
    [InlineData("v1.3.0-rc.1")] // a pre-release newer than the latest release
    public async Task SameOrNewerVersion_IsLatest(string current)
    {
        var (service, _) = Create(_ => Release("v1.2.0"));

        var result = await service.CheckAsync(current);

        Assert.Equal(UpdateStatus.Latest, result.Status);
    }

    [Fact]
    public async Task PreReleaseOfTheLatestVersion_IsOlder()
    {
        var (service, _) = Create(_ => Release("v1.2.0"));

        Assert.Equal(UpdateStatus.Available, (await service.CheckAsync("v1.2.0-rc.2")).Status);
    }

    [Fact]
    public async Task DevBuild_IsUnknown_ButShowsTheLatestRelease()
    {
        var (service, _) = Create(_ => Release("v1.2.0"));

        var result = await service.CheckAsync("dev");

        Assert.Equal(UpdateStatus.Unknown, result.Status);
        Assert.Equal("v1.2.0", result.LatestVersion);
    }

    [Theory]
    [InlineData(HttpStatusCode.NotFound, "{}")]
    [InlineData(HttpStatusCode.Forbidden, "{\"message\":\"rate limit\"}")]
    [InlineData(HttpStatusCode.OK, "not json")]
    [InlineData(HttpStatusCode.OK, "{\"tag_name\":\"<script>alert(1)</script>\"}")]
    [InlineData(HttpStatusCode.OK, "[]")]
    public async Task BadResponse_IsError(HttpStatusCode status, string body)
    {
        var (service, _) = Create(_ => new HttpResponseMessage(status) { Content = new StringContent(body) });

        var result = await service.CheckAsync("v1.0.0");

        Assert.Equal(UpdateStatus.Error, result.Status);
        Assert.Null(result.LatestVersion);
        Assert.Null(result.ReleaseUrl);
    }

    [Fact]
    public async Task NetworkFailure_IsError()
    {
        var (service, _) = Create(_ => throw new HttpRequestException("no route"));

        Assert.Equal(UpdateStatus.Error, (await service.CheckAsync("v1.0.0")).Status);
    }

    [Fact]
    public async Task Result_IsCached()
    {
        var (service, handler) = Create(_ => Release("v1.2.0"));

        await service.CheckAsync("v1.0.0");
        await service.CheckAsync("v1.2.0");

        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task Request_GoesToTheLatestReleaseApi()
    {
        Uri? requested = null;
        var (service, _) = Create(r => { requested = r.RequestUri; return Release("v1.0.0"); });

        await service.CheckAsync("v1.0.0");

        Assert.Equal(UpdateCheckService.LatestReleaseApi, requested?.ToString());
    }
}
