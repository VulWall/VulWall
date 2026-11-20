using Microsoft.Extensions.Caching.Memory;

namespace VulWall.Dashboard.Common.Services.RateLimiter;

/// <summary>
/// Counts attempts per endpoint in a fixed window. By default the counter is keyed on the
/// caller's IP; pass a <c>subject</c> (for example the admin account) to key it on that value
/// instead, so attempts from many IPs against one target share a single counter.
/// <para>
/// Callers reserve an attempt with <see cref="TryReserveAttempt"/> <em>before</em> the expensive
/// check and reset the counter only on success. Check-then-record would let N concurrent requests
/// all pass the check before any of them records a failure.
/// </para>
/// </summary>
public class IpRateLimiterService(IMemoryCache cache, IHttpContextAccessor httpContextAccessor)
{
    public const int DefaultMaxAttempts = 5;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(15);

    // One lock for every counter: the critical sections are a few instructions and only run on
    // login and change-password attempts. Static so instances sharing a cache stay consistent.
    private static readonly Lock Gate = new();

    private sealed class Counter
    {
        public int Count;
    }

    private string GetIp() =>
        httpContextAccessor.HttpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";

    /// <summary>
    /// Atomically counts one attempt. Returns false, without counting, when the limit is
    /// already reached.
    /// </summary>
    public bool TryReserveAttempt(string endpoint, string? subject = null, int maxAttempts = DefaultMaxAttempts)
    {
        var key = GetKey(endpoint, subject);
        lock (Gate)
        {
            var counter = GetOrCreateCounter(key);
            if (counter.Count >= maxAttempts)
                return false;
            counter.Count++;
            return true;
        }
    }

    public bool IsRateLimited(string endpoint, string? subject = null, int maxAttempts = DefaultMaxAttempts) =>
        GetCount(endpoint, subject) >= maxAttempts;

    /// <summary>Counts one failed attempt without checking the limit.</summary>
    public void RecordAttempt(string endpoint, string? subject = null)
    {
        var key = GetKey(endpoint, subject);
        lock (Gate)
        {
            GetOrCreateCounter(key).Count++;
        }
    }

    public void ResetAttempts(string endpoint, string? subject = null)
    {
        lock (Gate)
        {
            cache.Remove(GetKey(endpoint, subject));
        }
    }

    public int GetRemainingAttempts(string endpoint, string? subject = null, int maxAttempts = DefaultMaxAttempts) =>
        Math.Max(0, maxAttempts - GetCount(endpoint, subject));

    private int GetCount(string endpoint, string? subject)
    {
        lock (Gate)
        {
            return cache.Get<Counter>(GetKey(endpoint, subject))?.Count ?? 0;
        }
    }

    // Caller holds Gate. The window is fixed from the first attempt, as before.
    private Counter GetOrCreateCounter(string key)
    {
        if (cache.Get<Counter>(key) is { } existing)
            return existing;

        var counter = new Counter();
        cache.Set(key, counter, Window);
        return counter;
    }

    private string GetKey(string endpoint, string? subject) =>
        $"rate_limit:{endpoint}:{subject ?? GetIp()}";
}
