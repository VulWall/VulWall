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

    public async Task<UpdateCheckResult> CheckAsync(string currentVersion, CancellationToken ct = default)
    {
        if (!cache.TryGetValue(CacheKey, out string? latestTag))
        {
            latestTag = await FetchLatestTagAsync(ct);
            cache.Set(CacheKey, latestTag, latestTag is null ? ErrorCacheFor : CacheFor);
        }

        if (latestTag is null || !SemVer.TryParse(latestTag, out var latest))
            return new UpdateCheckResult(UpdateStatus.Error);

        var url = ReleaseTagUrl + Uri.EscapeDataString(latestTag);
        if (!SemVer.TryParse(currentVersion, out var current))
            return new UpdateCheckResult(UpdateStatus.Unknown, latestTag, url);

        return current.CompareTo(latest) >= 0
            ? new UpdateCheckResult(UpdateStatus.Latest, latestTag, url)
            : new UpdateCheckResult(UpdateStatus.Available, latestTag, url);
    }

    /// <summary>Returns the latest release tag, or null on any failure.</summary>
    private async Task<string?> FetchLatestTagAsync(CancellationToken ct)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(Timeout);
            using var response = await http.GetAsync(LatestReleaseApi, timeout.Token);
            if (!response.IsSuccessStatusCode)
            {
                logger.LogWarning("Update check: GitHub answered {Status}", (int)response.StatusCode);
                return null;
            }

            await using var body = await response.Content.ReadAsStreamAsync(timeout.Token);
            using var doc = await JsonDocument.ParseAsync(body, cancellationToken: timeout.Token);
            if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                doc.RootElement.TryGetProperty("tag_name", out var tag) &&
                tag.ValueKind == JsonValueKind.String &&
                tag.GetString() is { } value && SemVer.TryParse(value, out _))
            {
                return value;
            }

            logger.LogWarning("Update check: GitHub response has no valid tag_name");
            return null;
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or JsonException)
        {
            logger.LogWarning("Update check failed: {Error}", ex.GetType().Name);
            return null;
        }
    }

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
