using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using VulWall.Dashboard.Common.Services.RateLimiter;

namespace VulWall.Dashboard.Tests.Common;

public class IpRateLimiterServiceTests
{
    private const string Endpoint = "shared-reports";

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
    public void TokenCounter_IsSharedAcrossIps()
    {
        var cache = new MemoryCache(new MemoryCacheOptions());
        var first = new Caller(cache, "198.51.100.1").Limiter;
        var second = new Caller(cache, "198.51.100.2").Limiter;

        Fail(first, 3, "token-a");
        Fail(second, 2, "token-a");

        Assert.True(first.IsRateLimited(Endpoint, "token-a"));
        Assert.True(second.IsRateLimited(Endpoint, "token-a"));
        Assert.False(second.IsRateLimited(Endpoint)); // per-IP counter is separate
    }

    [Fact]
    public void ResettingOneToken_DoesNotResetAnotherTokenOrTheIpCounter()
    {
        var cache = new MemoryCache(new MemoryCacheOptions());
        var limiter = new Caller(cache, "198.51.100.1").Limiter;

        Fail(limiter, 5, "token-a");
        Fail(limiter, 5);
        limiter.RecordAttempt(Endpoint, "token-b");

        limiter.ResetAttempts(Endpoint, "token-b");

        Assert.True(limiter.IsRateLimited(Endpoint, "token-a"));
        Assert.True(limiter.IsRateLimited(Endpoint));
        Assert.Equal(5, limiter.GetRemainingAttempts(Endpoint, "token-b"));
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
}
