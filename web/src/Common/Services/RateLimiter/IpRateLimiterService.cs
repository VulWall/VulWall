using Microsoft.Extensions.Caching.Memory;

namespace VulWall.Dashboard.Common.Services.RateLimiter;

/// <summary>
/// Counts failed attempts per endpoint in a fixed window. By default the counter is keyed on the
/// caller's IP; pass a <c>subject</c> (for example a shared-link token) to key it on that value
/// instead, so attempts from many IPs against one target share a single counter.
/// </summary>
public class IpRateLimiterService(IMemoryCache cache, IHttpContextAccessor httpContextAccessor)
{
    private const int MaxAttempts = 5;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(15);

    private string GetIp() =>
        httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    public bool IsRateLimited(string endpoint, string? subject = null)
    {
        var key = GetKey(endpoint, subject);
        var attempts = cache.GetOrCreate(key, entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = Window;
            return 0;
        });

        return attempts >= MaxAttempts;
    }

    public void RecordAttempt(string endpoint, string? subject = null)
    {
        var key = GetKey(endpoint, subject);
        var attempts = cache.GetOrCreate(key, entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = Window;
            return 0;
        });

        cache.Set(key, attempts + 1, Window);
    }

    public void ResetAttempts(string endpoint, string? subject = null)
    {
        cache.Remove(GetKey(endpoint, subject));
    }

    public int GetRemainingAttempts(string endpoint, string? subject = null)
    {
        var attempts = cache.Get<int>(GetKey(endpoint, subject));
        return Math.Max(0, MaxAttempts - attempts);
    }

    private string GetKey(string endpoint, string? subject) =>
        $"rate_limit:{endpoint}:{subject ?? GetIp()}";
}
