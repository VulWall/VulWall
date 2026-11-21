using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Time.Testing;
using VulWall.Dashboard.About.Services;
using VulWall.Dashboard.Common.Services.UpdateCheck;

namespace VulWall.Dashboard.Tests.About;

public class UpdateCheckPollerTests
{
    private sealed class StubHandler : HttpMessageHandler
    {
        private int _calls;
        public int Calls => Volatile.Read(ref _calls);
        public Func<HttpResponseMessage> Respond { get; set; } = () => Release("v1.2.0");

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref _calls);
            return Task.FromResult(Respond());
        }
    }

    private static HttpResponseMessage Release(string tag) => new(HttpStatusCode.OK)
    {
        Content = new StringContent($$"""{"tag_name":"{{tag}}"}""")
    };

    private static HttpResponseMessage Unreachable() => throw new HttpRequestException("no route");

    private static HttpResponseMessage RateLimited(TimeSpan retryAfter)
    {
        var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
        response.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(retryAfter);
        return response;
    }

    /// <summary>Counts the delays the poller registers, so a test advances the clock only once one is waiting.</summary>
    private sealed class CountingTimeProvider : FakeTimeProvider
    {
        private int _timers;
        public int Timers => Volatile.Read(ref _timers);

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            var timer = base.CreateTimer(callback, state, dueTime, period);
            Interlocked.Increment(ref _timers);
            return timer;
        }
    }

    private static (UpdateCheckPoller Poller, UpdateCheckState State, StubHandler Handler, CountingTimeProvider Time)
        Create(bool enabled = true)
    {
        var handler = new StubHandler();
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHttpClient<UpdateCheckService>().ConfigurePrimaryHttpMessageHandler(() => handler);
        var provider = services.BuildServiceProvider();
        var state = new UpdateCheckState(enabled);
        var time = new CountingTimeProvider();
        var poller = new UpdateCheckPoller(provider.GetRequiredService<IServiceScopeFactory>(), state, time,
            NullLogger<UpdateCheckPoller>.Instance);
        return (poller, state, handler, time);
    }

    private static async Task WaitUntil(Func<bool> condition)
    {
        for (var i = 0; i < 200 && !condition(); i++)
            await Task.Delay(10);
        Assert.True(condition());
    }

    [Fact]
    public async Task ChecksAfterTheStartDelay_ThenEverySixHours()
    {
        var (poller, state, handler, time) = Create();
        await poller.StartAsync(CancellationToken.None);
        try
        {
            Assert.Equal(UpdateStatus.NotChecked, state.Current.Status);
            // BackgroundService runs ExecuteAsync on a thread-pool thread: wait until each delay is registered.
            await WaitUntil(() => time.Timers == 1);

            time.Advance(UpdateCheckPoller.StartDelay - TimeSpan.FromSeconds(1));
            await Task.Delay(50);
            Assert.Equal(0, handler.Calls);

            time.Advance(TimeSpan.FromSeconds(1));
            await WaitUntil(() => handler.Calls == 1 && state.Current.Status != UpdateStatus.NotChecked);
            await WaitUntil(() => time.Timers == 2);

            time.Advance(UpdateCheckPoller.Interval - TimeSpan.FromMinutes(1));
            await Task.Delay(50);
            Assert.Equal(1, handler.Calls);

            time.Advance(TimeSpan.FromMinutes(1));
            await WaitUntil(() => handler.Calls == 2);
        }
        finally
        {
            await poller.StopAsync(CancellationToken.None);
        }
    }

    [Fact]
    public async Task Disabled_NeverAsksGitHub()
    {
        var (poller, state, handler, time) = Create(enabled: false);
        await poller.StartAsync(CancellationToken.None);
        await (poller.ExecuteTask ?? Task.CompletedTask);

        time.Advance(TimeSpan.FromDays(2));
        await Task.Delay(50);
        await poller.StopAsync(CancellationToken.None);

        Assert.Equal(0, handler.Calls);
        Assert.Equal(UpdateStatus.Off, state.Current.Status);
        Assert.Null(state.Current.AvailableVersion);
    }

    [Fact]
    public async Task NewerRelease_IsStored_ForTheSidebarBadge()
    {
        var (poller, state, _, _) = Create();

        var next = await poller.CheckOnceAsync("v1.0.0", CancellationToken.None);

        Assert.Equal(UpdateCheckPoller.Interval, next);
        Assert.Equal(UpdateStatus.Available, state.Current.Status);
        Assert.Equal("v1.2.0", state.Current.AvailableVersion);
    }

    [Theory]
    [InlineData("dev")]
    [InlineData("dev (abc1234)")]
    public async Task DevBuild_NeverGetsTheBadge(string current)
    {
        var (poller, state, _, _) = Create();

        await poller.CheckOnceAsync(current, CancellationToken.None);

        Assert.Equal(UpdateStatus.Unknown, state.Current.Status);
        Assert.Equal("v1.2.0", state.Current.LatestVersion);
        Assert.Null(state.Current.AvailableVersion);
    }

    [Fact]
    public async Task Failures_BackOff_From15MinutesUpToTheInterval_AndSuccessResets()
    {
        var (poller, _, handler, _) = Create();
        handler.Respond = Unreachable;

        var delays = new List<TimeSpan>();
        for (var i = 0; i < 7; i++)
            delays.Add(await poller.CheckOnceAsync("v1.0.0", CancellationToken.None));

        Assert.Equal(new[] { 15, 30, 60, 120, 240, 360, 360 }, delays.Select(d => (int)d.TotalMinutes));

        handler.Respond = () => Release("v1.2.0");
        Assert.Equal(UpdateCheckPoller.Interval, await poller.CheckOnceAsync("v1.0.0", CancellationToken.None));
        handler.Respond = Unreachable;
        Assert.Equal(UpdateCheckPoller.FirstRetry, await poller.CheckOnceAsync("v1.0.0", CancellationToken.None));
    }

    [Fact]
    public async Task RateLimit_WaitsForGitHubsReset_WhenLongerThanTheBackoff()
    {
        var (poller, state, handler, _) = Create();
        handler.Respond = () => RateLimited(TimeSpan.FromMinutes(40));

        var next = await poller.CheckOnceAsync("v1.0.0", CancellationToken.None);

        Assert.Equal(TimeSpan.FromMinutes(40), next);
        Assert.Equal(UpdateStatus.RateLimited, state.Current.Status);
    }

    [Fact]
    public async Task FailedRecheck_KeepsTheLastAnswer()
    {
        var (poller, state, handler, _) = Create();
        await poller.CheckOnceAsync("v1.0.0", CancellationToken.None);
        handler.Respond = Unreachable;

        await poller.CheckOnceAsync("v1.0.0", CancellationToken.None);

        Assert.Equal(UpdateStatus.Available, state.Current.Status);
        Assert.Equal("v1.2.0", state.Current.AvailableVersion);
    }

    [Fact]
    public async Task FirstCheckFailing_ShowsTheFailure()
    {
        var (poller, state, handler, _) = Create();
        handler.Respond = Unreachable;

        await poller.CheckOnceAsync("v1.0.0", CancellationToken.None);

        Assert.Equal(UpdateStatus.Unreachable, state.Current.Status);
    }

    [Fact]
    public async Task CancelledCheck_Throws_AndLeavesTheStateAlone()
    {
        var (poller, state, _, _) = Create();
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => poller.CheckOnceAsync("v1.0.0", cts.Token));

        Assert.Equal(UpdateStatus.NotChecked, state.Current.Status);
    }

    [Theory]
    [InlineData(null, true)]
    [InlineData("", true)]
    [InlineData("true", true)]
    [InlineData("yes", true)]
    [InlineData("false", false)]
    [InlineData(" FALSE ", false)]
    [InlineData("0", false)]
    [InlineData("off", false)]
    [InlineData("no", false)]
    public void UpdateCheckSetting_IsOnUnlessTurnedOff(string? value, bool on) =>
        Assert.Equal(on, VulWall.Dashboard.Common.Utils.ServiceSettings.IsOn(value));

    [Theory]
    [InlineData(UpdateStatus.Available, "v1.2.0")]
    [InlineData(UpdateStatus.Latest, null)]
    [InlineData(UpdateStatus.Unknown, null)]
    [InlineData(UpdateStatus.Unreachable, null)]
    [InlineData(UpdateStatus.Off, null)]
    public void SidebarBadge_OnlyForAvailable(UpdateStatus status, string? badge) =>
        Assert.Equal(badge, new UpdateCheckResult(status, "v1.2.0").AvailableVersion);
}
