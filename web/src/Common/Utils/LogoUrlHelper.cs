using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Microsoft.Extensions.FileProviders;

namespace VulWall.Dashboard.Common.Utils;

/// <summary>
/// Resolves country-flag and cloud-provider logo images served from wwwroot/images/logos.
/// Returns null when the image is not shipped, so the view renders a generic icon instead.
/// Inputs come from scan data in the database, so only safe slugs ever reach a file path.
/// </summary>
public static partial class LogoUrlHelper
{
    private const string BasePath = "/images/logos";

    // File existence per web root and path, cached for the process lifetime (wwwroot is
    // read-only at runtime).
    private static readonly ConditionalWeakTable<IFileProvider, ConcurrentDictionary<string, bool>> ExistsCache = new();

    /// <param name="webRoot">The app's web root, IWebHostEnvironment.WebRootFileProvider.</param>
    /// <param name="countryCode">ISO 3166-1 alpha-2 code (e.g., "NL", "US").</param>
    public static string? GetCountryFlagUrl(IFileProvider webRoot, string? countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode))
            return null;

        var code = countryCode.Trim().ToLowerInvariant();
        return CountryCodeRegex().IsMatch(code) ? Resolve(webRoot, $"{BasePath}/countries/{code}.png") : null;
    }

    /// <param name="webRoot">The app's web root, IWebHostEnvironment.WebRootFileProvider.</param>
    /// <param name="provider">Cloud provider or ISP name (e.g., "AWS", "Cloudflare, Inc.").</param>
    public static string? GetCloudProviderLogoUrl(IFileProvider webRoot, string? provider)
    {
        var slug = NormalizeProviderName(provider);
        return slug == null ? null : Resolve(webRoot, $"{BasePath}/cloud/{slug}.png");
    }

    /// <summary>
    /// Maps a provider/ISP name to a logo file slug of [a-z0-9-] characters, or null.
    /// </summary>
    internal static string? NormalizeProviderName(string? provider)
    {
        if (string.IsNullOrWhiteSpace(provider))
            return null;

        var name = provider.Trim().ToLowerInvariant();
        if (name.Contains("cloudflare"))
            return "cloudflare";

        var slug = NonSlugRegex().Replace(name, "-").Trim('-');
        return slug.Length is > 0 and <= 64 ? slug : null;
    }

    private static string? Resolve(IFileProvider webRoot, string path) =>
        ExistsCache.GetOrCreateValue(webRoot).GetOrAdd(path, p => webRoot.GetFileInfo(p).Exists) ? path : null;

    [GeneratedRegex("^[a-z]{2}$")]
    private static partial Regex CountryCodeRegex();

    [GeneratedRegex("[^a-z0-9]+")]
    private static partial Regex NonSlugRegex();
}
