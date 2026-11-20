using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using VulWall.Dashboard.Common.Services.RateLimiter;

namespace VulWall.Dashboard.Tests.Common;

public class IpRateLimiterServiceTests
{
    private const string Endpoint = "login";

    // HttpContextAccessor keeps its context in a static AsyncLocal, so two instances in one test
    // would share it. A plain fixed accessor gives each simulated caller its own IP.
    private sealed class FixedAccessor(string ip) : IHttpContextAccessor
    {
        public HttpContext? HttpContext { get; set; } = new DefaultHttpContext
        {
            Connection = { RemoteIpAddress = IPAddress.Parse(ip) }
        };
    }

    private sealed class Caller(IMemoryCache cache, string ip)
    {
        public IpRateLimiterService Limiter { get; } = new(cache, new FixedAccessor(ip));
    }

    private static void Fail(IpRateLimiterService limiter, int times, string? subject = null)
    {
        for (var i = 0; i < times; i++)
            limiter.RecordAttempt(Endpoint, subject);
    }

    [Fact]
    public void SubjectCounter_IsSharedAcrossIps()
    {
        var cache = new MemoryCache(new MemoryCacheOptions());
        var first = new Caller(cache, "198.51.100.1").Limiter;
        var second = new Caller(cache, "198.51.100.2").Limiter;

        Fail(first, 3, "subject-a");
        Fail(second, 2, "subject-a");

        Assert.True(first.IsRateLimited(Endpoint, "subject-a"));
        Assert.True(second.IsRateLimited(Endpoint, "subject-a"));
        Assert.False(second.IsRateLimited(Endpoint)); // per-IP counter is separate
    }

    [Fact]
    public void ResettingOneSubject_DoesNotResetAnotherSubjectOrTheIpCounter()
    {
        var cache = new MemoryCache(new MemoryCacheOptions());
        var limiter = new Caller(cache, "198.51.100.1").Limiter;

        Fail(limiter, 5, "subject-a");
        Fail(limiter, 5);
        limiter.RecordAttempt(Endpoint, "subject-b");

        limiter.ResetAttempts(Endpoint, "subject-b");

        Assert.True(limiter.IsRateLimited(Endpoint, "subject-a"));
        Assert.True(limiter.IsRateLimited(Endpoint));
        Assert.Equal(5, limiter.GetRemainingAttempts(Endpoint, "subject-b"));
    }

    [Fact]
    public void IpCounter_IsPerIp()
    {
        var cache = new MemoryCache(new MemoryCacheOptions());
        var first = new Caller(cache, "198.51.100.1").Limiter;
        var second = new Caller(cache, "198.51.100.2").Limiter;

        Fail(first, 5);

        Assert.True(first.IsRateLimited(Endpoint));
        Assert.False(second.IsRateLimited(Endpoint));
        Assert.Equal(0, first.GetRemainingAttempts(Endpoint));
        Assert.Equal(5, second.GetRemainingAttempts(Endpoint));
    }

    [Fact]
    public void TryReserveAttempt_CountsUpToTheLimitThenRefuses()
    {
        var limiter = new Caller(new MemoryCache(new MemoryCacheOptions()), "198.51.100.1").Limiter;

        for (var i = 0; i < 3; i++)
            Assert.True(limiter.TryReserveAttempt(Endpoint, maxAttempts: 3));

        Assert.False(limiter.TryReserveAttempt(Endpoint, maxAttempts: 3));
        Assert.Equal(0, limiter.GetRemainingAttempts(Endpoint, maxAttempts: 3));
    }

    [Fact]
    public async Task TryReserveAttempt_ParallelAttempts_AreAllCounted()
    {
        const int attempts = 200;
        var cache = new MemoryCache(new MemoryCacheOptions());
        var limiters = Enumerable.Range(0, 8).Select(_ => new Caller(cache, "198.51.100.1").Limiter).ToList();
        using var start = new ManualResetEventSlim();

        var tasks = Enumerable.Range(0, attempts).Select(i => Task.Run(() =>
        {
            start.Wait();
            return limiters[i % limiters.Count].TryReserveAttempt(Endpoint, maxAttempts: 1000);
        })).ToList();
        start.Set();
        await Task.WhenAll(tasks);

        Assert.All(tasks, t => Assert.True(t.Result));
        Assert.Equal(1000 - attempts, limiters[0].GetRemainingAttempts(Endpoint, maxAttempts: 1000));
    }

    [Fact]
    public async Task TryReserveAttempt_ParallelAttemptsPastTheLimit_LetExactlyTheLimitThrough()
    {
        var limiter = new Caller(new MemoryCache(new MemoryCacheOptions()), "198.51.100.1").Limiter;

        var results = await Task.WhenAll(Enumerable.Range(0, 100)
            .Select(_ => Task.Run(() => limiter.TryReserveAttempt(Endpoint, "subject-a"))));

        Assert.Equal(IpRateLimiterService.DefaultMaxAttempts, results.Count(r => r));
    }
}
