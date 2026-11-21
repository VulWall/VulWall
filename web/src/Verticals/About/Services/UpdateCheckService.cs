using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.RegularExpressions;
using VulWall.Dashboard.Common.Services.UpdateCheck;

namespace VulWall.Dashboard.About.Services;

/// <summary>
/// Asks GitHub for the latest VulWall release, from the server so the browser CSP keeps connect-src 'self'.
/// Only <see cref="UpdateCheckPoller"/> calls it (at start, then every 6 hours), never a page load.
/// </summary>
public partial class UpdateCheckService(HttpClient http, ILogger<UpdateCheckService> logger)
{
    public const string LatestReleaseApi = "https://api.github.com/repos/VulWall/VulWall/releases/latest";
    private const string ReleaseTagUrl = "https://github.com/VulWall/VulWall/releases/tag/";
    private static readonly TimeSpan MinRateLimitWait = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan MaxRateLimitWait = TimeSpan.FromHours(1);

    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(5);

    /// <summary>
    /// One request to GitHub. Every failure is a result; <c>RateLimitWait</c> is GitHub's reset time for a
    /// rate-limit answer. Only a cancelled request (shutdown) throws.
    /// </summary>
    public async Task<(UpdateCheckResult Result, TimeSpan? RateLimitWait)> CheckAsync(string currentVersion,
        CancellationToken ct = default)
    {
        var (tag, failure, wait) = await FetchAsync(ct);
        if (tag is null || !SemVer.TryParse(tag, out var latest))
            return (new UpdateCheckResult(tag is null ? failure : UpdateStatus.Error), wait);

        var label = "v" + tag.TrimStart('v');
        var url = ReleaseTagUrl + Uri.EscapeDataString(tag);
        // Not a release version, for example "dev" or "dev (abc1234)" from a local build.
        if (!SemVer.TryParse(currentVersion, out var current))
            return (new UpdateCheckResult(UpdateStatus.Unknown, label, url), null);

        return (current.CompareTo(latest) >= 0
            ? new UpdateCheckResult(UpdateStatus.Latest, label, url)
            : new UpdateCheckResult(UpdateStatus.Available, label, url), null);
    }

    /// <summary>The latest release tag, or a null tag with the failure status.</summary>
    private async Task<(string? Tag, UpdateStatus Failure, TimeSpan? RateLimitWait)> FetchAsync(CancellationToken ct)
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
                    return (null, UpdateStatus.NoRelease, null);
                if (IsRateLimited(response))
                    return (null, UpdateStatus.RateLimited, RateLimitWait(response.Headers, DateTimeOffset.UtcNow));
                return (null, UpdateStatus.Error, null);
            }

            await using var body = await response.Content.ReadAsStreamAsync(timeout.Token);
            using var doc = await JsonDocument.ParseAsync(body, cancellationToken: timeout.Token);
            if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                doc.RootElement.TryGetProperty("tag_name", out var tag) &&
                tag.ValueKind == JsonValueKind.String &&
                tag.GetString() is { } value && SemVer.TryParse(value, out _))
            {
                return (value.Trim(), UpdateStatus.Error, null);
            }

            logger.LogWarning("Update check: GitHub response has no valid tag_name");
            return (null, UpdateStatus.Error, null);
        }
        catch (JsonException)
        {
            logger.LogWarning("Update check: GitHub response is not JSON");
            return (null, UpdateStatus.Error, null);
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException && !ct.IsCancellationRequested)
        {
            // Connection failure, DNS failure or our timeout.
            logger.LogWarning("Update check failed: {Error}", ex.GetType().Name);
            return (null, UpdateStatus.Unreachable, null);
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
    /// How long to wait after a rate-limit answer: until GitHub's reset time (Retry-After, else
    /// X-RateLimit-Reset in Unix seconds), at least 1 minute and at most 1 hour. 1 minute without
    /// either header.
    /// </summary>
    internal static TimeSpan RateLimitWait(HttpResponseHeaders headers, DateTimeOffset now)
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
            return MinRateLimitWait;
        return w < MinRateLimitWait ? MinRateLimitWait : w > MaxRateLimitWait ? MaxRateLimitWait : w;
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
