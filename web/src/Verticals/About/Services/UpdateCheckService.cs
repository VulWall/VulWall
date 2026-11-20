using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Caching.Memory;
using VulWall.Dashboard.About.Models;

namespace VulWall.Dashboard.About.Services;

/// <summary>
/// Asks GitHub for the latest VulWall release. Runs only when the admin clicks "Check for updates"
/// (never on a schedule), from the server so the browser CSP keeps connect-src 'self'.
/// </summary>
public partial class UpdateCheckService(HttpClient http, IMemoryCache cache, ILogger<UpdateCheckService> logger)
{
    public const string LatestReleaseApi = "https://api.github.com/repos/VulWall/VulWall/releases/latest";
    private const string ReleaseTagUrl = "https://github.com/VulWall/VulWall/releases/tag/";
    private const string CacheKey = "about:latest-release";
    private static readonly TimeSpan CacheFor = TimeSpan.FromHours(1);
    // A failure is cached briefly so repeated clicks do not hammer GitHub's unauthenticated rate limit.
    private static readonly TimeSpan ErrorCacheFor = TimeSpan.FromMinutes(1);

    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    /// <summary>A fetch result: the latest tag, or the failure status (with a null tag).</summary>
    private sealed record Fetched(string? Tag, UpdateStatus Failure);

    public async Task<UpdateCheckResult> CheckAsync(string currentVersion, CancellationToken ct = default)
    {
        if (!cache.TryGetValue(CacheKey, out Fetched? fetched) || fetched is null)
        {
            var (result, cacheFor) = await FetchAsync(ct);
            fetched = result;
            cache.Set(CacheKey, fetched, cacheFor);
        }

        if (fetched.Tag is null || !SemVer.TryParse(fetched.Tag, out var latest))
            return new UpdateCheckResult(fetched.Tag is null ? fetched.Failure : UpdateStatus.Error);

        var url = ReleaseTagUrl + Uri.EscapeDataString(fetched.Tag);
        // Not a release version, for example "dev" or "dev (abc1234)" from a local build.
        if (!SemVer.TryParse(currentVersion, out var current))
            return new UpdateCheckResult(UpdateStatus.Unknown, fetched.Tag, url);

        return current.CompareTo(latest) >= 0
            ? new UpdateCheckResult(UpdateStatus.Latest, fetched.Tag, url)
            : new UpdateCheckResult(UpdateStatus.Available, fetched.Tag, url);
    }

    /// <summary>
    /// Asks GitHub for the latest release tag. Every failure is a result, cached for a while; only a
    /// cancelled request (the browser went away) throws, so it is never cached.
    /// </summary>
    private async Task<(Fetched Result, TimeSpan CacheFor)> FetchAsync(CancellationToken ct)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(Timeout);
            using var response = await http.GetAsync(LatestReleaseApi, timeout.Token);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Update check: GitHub answered {Status}", (int)response.StatusCode);
                if (response.StatusCode == HttpStatusCode.NotFound)
                    return (new Fetched(null, UpdateStatus.NoRelease), ErrorCacheFor);
                if (IsRateLimited(response))
                    return (new Fetched(null, UpdateStatus.RateLimited), RateLimitCacheFor(response.Headers, DateTimeOffset.UtcNow));
                return (new Fetched(null, UpdateStatus.Error), ErrorCacheFor);
            }

            await using var body = await response.Content.ReadAsStreamAsync(timeout.Token);
            using var doc = await JsonDocument.ParseAsync(body, cancellationToken: timeout.Token);
            if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                doc.RootElement.TryGetProperty("tag_name", out var tag) &&
                tag.ValueKind == JsonValueKind.String &&
                tag.GetString() is { } value && SemVer.TryParse(value, out _))
            {
                return (new Fetched(value, UpdateStatus.Error), CacheFor);
            }

            logger.LogWarning("Update check: GitHub response has no valid tag_name");
            return (new Fetched(null, UpdateStatus.Error), ErrorCacheFor);
        }
        catch (JsonException)
        {
            logger.LogWarning("Update check: GitHub response is not JSON");
            return (new Fetched(null, UpdateStatus.Error), ErrorCacheFor);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            // Connection failure, DNS failure or our timeout.
            logger.LogWarning("Update check failed: {Error}", ex.GetType().Name);
            return (new Fetched(null, UpdateStatus.Unreachable), ErrorCacheFor);
        }
    }

    /// <summary>
    /// GitHub's rate limit answer: 429, or 403 with X-RateLimit-Remaining: 0 or Retry-After (a
    /// secondary limit). Any other 403 is a plain error.
    /// </summary>
    internal static bool IsRateLimited(HttpResponseMessage response) =>
        response.StatusCode == HttpStatusCode.TooManyRequests ||
        (response.StatusCode == HttpStatusCode.Forbidden &&
         (Header(response.Headers, "X-RateLimit-Remaining") == "0" || response.Headers.RetryAfter is not null));

    /// <summary>
    /// How long to keep a rate-limit answer: until GitHub's reset time (Retry-After, else
    /// X-RateLimit-Reset in Unix seconds), at least 1 minute and at most 1 hour. 1 minute without
    /// either header.
    /// </summary>
    internal static TimeSpan RateLimitCacheFor(HttpResponseHeaders headers, DateTimeOffset now)
    {
        TimeSpan? wait = null;
        if (headers.RetryAfter?.Delta is { } delta)
            wait = delta;
        else if (headers.RetryAfter?.Date is { } date)
            wait = date - now;
        else if (long.TryParse(Header(headers, "X-RateLimit-Reset"), out var reset) &&
                 reset is > 0 and < 253402300800) // before year 10000, or FromUnixTimeSeconds throws
            wait = DateTimeOffset.FromUnixTimeSeconds(reset) - now;

        if (wait is not { } w)
            return ErrorCacheFor;
        return w < ErrorCacheFor ? ErrorCacheFor : w > CacheFor ? CacheFor : w;
    }

    private static string? Header(HttpResponseHeaders headers, string name) =>
        headers.TryGetValues(name, out var values) ? values.FirstOrDefault()?.Trim() : null;

    /// <summary>
    /// Enough semantic versioning for release tags: v-prefix optional; a pre-release sorts before its
    /// release, and two pre-releases of the same version compare ordinally.
    /// </summary>
    internal readonly partial record struct SemVer(int Major, int Minor, int Patch, string PreRelease)
        : IComparable<SemVer>
    {
        [GeneratedRegex(@"^v?(\d{1,9})\.(\d{1,9})\.(\d{1,9})(?:-([0-9A-Za-z.-]{1,40}))?$")]
        private static partial Regex Pattern();

        public static bool TryParse(string? value, out SemVer version)
        {
            version = default;
            var m = value is null ? null : Pattern().Match(value.Trim());
            if (m is not { Success: true })
                return false;
            version = new SemVer(int.Parse(m.Groups[1].Value), int.Parse(m.Groups[2].Value),
                int.Parse(m.Groups[3].Value), m.Groups[4].Value);
            return true;
        }

        public int CompareTo(SemVer other)
        {
            var c = (Major, Minor, Patch).CompareTo((other.Major, other.Minor, other.Patch));
            if (c != 0) return c;
            if (PreRelease == other.PreRelease) return 0;
            if (PreRelease.Length == 0) return 1;
            if (other.PreRelease.Length == 0) return -1;
            return string.CompareOrdinal(PreRelease, other.PreRelease);
        }
    }
}
