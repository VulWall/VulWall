using System.Net;
using System.Net.Http.Headers;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using VulWall.Dashboard.About.Services;
using VulWall.Dashboard.Common.Services.UpdateCheck;

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

    // A fixed clock: GitHub's rate-limit reset is compared with it.
    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

    private static (UpdateCheckService Service, StubHandler Handler) Create(Func<HttpRequestMessage, HttpResponseMessage> respond)
    {
        var handler = new StubHandler(respond);
        var http = new HttpClient(handler) { MaxResponseContentBufferSize = UpdateCheckService.MaxResponseBytes };
        var service = new UpdateCheckService(http, new FakeTimeProvider(Now), NullLogger<UpdateCheckService>.Instance);
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

        var (result, _) = await service.CheckAsync("v1.1.9");

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

        var (result, _) = await service.CheckAsync(current);

        Assert.Equal(UpdateStatus.Latest, result.Status);
    }

    [Fact]
    public async Task PreReleaseOfTheLatestVersion_IsOlder()
    {
        var (service, _) = Create(_ => Release("v1.2.0"));

        Assert.Equal(UpdateStatus.Available, (await service.CheckAsync("v1.2.0-rc.2")).Result.Status);
    }

    [Fact]
    public async Task DevBuild_IsUnknown_ButShowsTheLatestRelease()
    {
        var (service, _) = Create(_ => Release("v1.2.0"));

        var (result, _) = await service.CheckAsync("dev");

        Assert.Equal(UpdateStatus.Unknown, result.Status);
        Assert.Equal("v1.2.0", result.LatestVersion);
    }

    [Theory]
    [InlineData(HttpStatusCode.Forbidden, "{\"message\":\"forbidden\"}")] // a 403 without rate-limit headers
    [InlineData(HttpStatusCode.InternalServerError, "{}")]
    [InlineData(HttpStatusCode.OK, "not json")]
    [InlineData(HttpStatusCode.OK, "{\"tag_name\":\"<script>alert(1)</script>\"}")]
    [InlineData(HttpStatusCode.OK, "[]")]
    public async Task BadResponse_IsError(HttpStatusCode status, string body)
    {
        var (service, _) = Create(_ => new HttpResponseMessage(status) { Content = new StringContent(body) });

        var (result, _) = await service.CheckAsync("v1.0.0");

        Assert.Equal(UpdateStatus.Error, result.Status);
        Assert.Null(result.LatestVersion);
        Assert.Null(result.ReleaseUrl);
    }

    [Theory]
    [InlineData("v1.0.0")]
    [InlineData("dev (abc1234)")]
    public async Task NoRelease_IsNoRelease(string current)
    {
        var (service, _) = Create(_ => new HttpResponseMessage(HttpStatusCode.NotFound) { Content = new StringContent("{}") });

        var (result, _) = await service.CheckAsync(current);

        Assert.Equal(UpdateStatus.NoRelease, result.Status);
        Assert.Null(result.LatestVersion);
        Assert.Null(result.ReleaseUrl);
    }

    private static HttpResponseMessage RateLimited(HttpStatusCode status)
    {
        var response = new HttpResponseMessage(status) { Content = new StringContent("{\"message\":\"API rate limit exceeded\"}") };
        response.Headers.Add("X-RateLimit-Remaining", "0");
        response.Headers.Add("X-RateLimit-Reset", Now.AddMinutes(30).ToUnixTimeSeconds().ToString());
        return response;
    }

    [Theory]
    [InlineData(HttpStatusCode.Forbidden)]
    [InlineData(HttpStatusCode.TooManyRequests)]
    public async Task RateLimit_IsRateLimited_WithTheWaitUntilTheReset(HttpStatusCode status)
    {
        var (service, _) = Create(_ => RateLimited(status));

        var (result, wait) = await service.CheckAsync("v1.0.0");

        Assert.Equal(UpdateStatus.RateLimited, result.Status);
        Assert.Equal(TimeSpan.FromMinutes(30), wait);
    }

    [Fact]
    public async Task OversizedResponse_FailsTheCheck()
    {
        var huge = "{\"tag_name\":\"v9.0.0\",\"body\":\"" + new string('a', UpdateCheckService.MaxResponseBytes) + "\"}";
        var (service, _) = Create(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(huge) });

        var (result, _) = await service.CheckAsync("v1.0.0");

        Assert.NotEqual(UpdateStatus.Available, result.Status);
        Assert.Null(result.LatestVersion);
    }

    [Fact]
    public async Task NonAsciiDigits_AreNotAVersion()
    {
        // Arabic-Indic digits: \d would match them and int.Parse would then throw.
        var (service, _) = Create(_ => Release("v\u0661.\u0662.\u0663"));

        var (result, _) = await service.CheckAsync("v1.0.0");

        Assert.Equal(UpdateStatus.Error, result.Status);
    }

    [Fact]
    public async Task TooManyRequests_WithoutHeaders_IsRateLimited()
    {
        var (service, _) = Create(_ => new HttpResponseMessage(HttpStatusCode.TooManyRequests));

        Assert.Equal(UpdateStatus.RateLimited, (await service.CheckAsync("v1.0.0")).Result.Status);
    }

    [Fact]
    public void RateLimitWait_LastsUntilTheReset_BetweenOneMinuteAndOneHour()
    {
        var now = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);
        TimeSpan For(Action<HttpResponseMessage> set)
        {
            var response = new HttpResponseMessage(HttpStatusCode.Forbidden);
            set(response);
            return UpdateCheckService.RateLimitWait(response.Headers, now);
        }

        Assert.Equal(TimeSpan.FromMinutes(20),
            For(r => r.Headers.Add("X-RateLimit-Reset", now.AddMinutes(20).ToUnixTimeSeconds().ToString())));
        Assert.Equal(TimeSpan.FromHours(1),
            For(r => r.Headers.Add("X-RateLimit-Reset", now.AddHours(5).ToUnixTimeSeconds().ToString())));
        Assert.Equal(TimeSpan.FromMinutes(1),
            For(r => r.Headers.Add("X-RateLimit-Reset", now.AddMinutes(-5).ToUnixTimeSeconds().ToString())));
        Assert.Equal(TimeSpan.FromMinutes(1), For(r => r.Headers.Add("X-RateLimit-Reset", "not a number")));
        Assert.Equal(TimeSpan.FromMinutes(1), For(r => r.Headers.Add("X-RateLimit-Reset", "99999999999999")));
        Assert.Equal(TimeSpan.FromMinutes(1), For(_ => { }));
        Assert.Equal(TimeSpan.FromMinutes(10),
            For(r => r.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromMinutes(10))));
    }

    [Fact]
    public async Task NetworkFailure_IsUnreachable()
    {
        var (service, _) = Create(_ => throw new HttpRequestException("no route"));

        Assert.Equal(UpdateStatus.Unreachable, (await service.CheckAsync("v1.0.0")).Result.Status);
    }

    [Fact]
    public async Task Timeout_IsUnreachable()
    {
        var (service, _) = Create(_ => throw new TaskCanceledException("timeout"));

        Assert.Equal(UpdateStatus.Unreachable, (await service.CheckAsync("v1.0.0")).Result.Status);
    }

    [Fact]
    public async Task CancelledRequest_Throws()
    {
        var (service, _) = Create(_ => Release("v1.2.0"));
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.CheckAsync("v1.0.0", cts.Token));
    }

    [Fact]
    public async Task DevBuildWithCommit_IsUnknown()
    {
        var (service, _) = Create(_ => Release("v1.2.0"));

        Assert.Equal(UpdateStatus.Unknown, (await service.CheckAsync("dev (abc1234)")).Result.Status);
    }

    [Fact]
    public async Task EachCheck_IsOneRequest()
    {
        var (service, handler) = Create(_ => Release("v1.2.0"));

        await service.CheckAsync("v1.0.0");

        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task TagWithoutV_IsShownWithV()
    {
        var (service, _) = Create(_ => Release("1.2.0"));

        var (result, _) = await service.CheckAsync("v1.0.0");

        Assert.Equal("v1.2.0", result.LatestVersion);
        Assert.Equal("https://github.com/VulWall/VulWall/releases/tag/1.2.0", result.ReleaseUrl);
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
