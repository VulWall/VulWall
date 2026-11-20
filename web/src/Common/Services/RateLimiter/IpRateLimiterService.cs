using Microsoft.Extensions.Caching.Memory;

namespace VulWall.Dashboard.Common.Services.RateLimiter;

public class IpRateLimiterService(IMemoryCache cache, IHttpContextAccessor httpContextAccessor)
{
    private const int MaxAttempts = 5;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(15);

    private string GetIp() =>
        httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    public bool IsRateLimited(string endpoint)
    {
        var key = GetKey(GetIp(), endpoint);
        var attempts = cache.GetOrCreate(key, entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = Window;
            return 0;
        });

        return attempts >= MaxAttempts;
    }

    public void RecordAttempt(string endpoint)
    {
        var key = GetKey(GetIp(), endpoint);
        var attempts = cache.GetOrCreate(key, entry =>
        {
            entry.AbsoluteExpirationRelativeToNow = Window;
            return 0;
        });

        cache.Set(key, attempts + 1, Window);
    }

    public void ResetAttempts(string endpoint)
    {
        var key = GetKey(GetIp(), endpoint);
        cache.Remove(key);
    }

    public int GetRemainingAttempts(string endpoint)
    {
        var key = GetKey(GetIp(), endpoint);
        var attempts = cache.Get<int>(key);
        return Math.Max(0, MaxAttempts - attempts);
    }

    private static string GetKey(string ipAddress, string endpoint)
    {
        return $"rate_limit:{endpoint}:{ipAddress}";
    }
}
