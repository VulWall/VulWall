using System.Net;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using VulWall.Dashboard.Common.Services.NightWatch;
using VulWall.Dashboard.Common.Services.NightWatch.Models;

namespace VulWall.Dashboard.Tests.Common;

public class NightWatchServiceTests
{
    private sealed class StubHandler(HttpStatusCode status, string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(status)
            {
                Content = new StringContent(body, Encoding.UTF8, "application/json")
            });
    }

    private static NightWatchService CreateService(HttpStatusCode status, string body) =>
        new(new HttpClient(new StubHandler(status, body)), NullLogger<NightWatchService>.Instance);

    [Fact]
    public async Task TriggerScanAsync_Accepted_ReturnsStartedWithScanId()
    {
        var service = CreateService(HttpStatusCode.Accepted, """{"scan_id":"scan-1"}""");

        var result = await service.TriggerScanAsync("org-1", "user@example.com");

        Assert.Equal(TriggerScanOutcome.Started, result.Outcome);
        Assert.Equal("scan-1", result.ScanId);
    }

    [Fact]
    public async Task TriggerScanAsync_Conflict_ReturnsAlreadyRunning()
    {
        var service = CreateService(HttpStatusCode.Conflict, """{"error":"scan already running"}""");

        var result = await service.TriggerScanAsync("org-1", "user@example.com");

        Assert.Equal(TriggerScanOutcome.AlreadyRunning, result.Outcome);
        Assert.Null(result.ScanId);
    }

    [Fact]
    public async Task TriggerScanAsync_ServerError_ReturnsFailed()
    {
        var service = CreateService(HttpStatusCode.InternalServerError, "{}");

        var result = await service.TriggerScanAsync("org-1", "user@example.com");

        Assert.Equal(TriggerScanOutcome.Failed, result.Outcome);
    }
}
