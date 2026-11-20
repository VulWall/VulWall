namespace VulWall.Dashboard.Common.Utils;

/// <summary>
/// Helper class for generating logo URLs for geographic and cloud provider indicators
/// </summary>
public static class LogoUrlHelper
{
    private const string BaseUrl = "https://assets.vulwall.com/logos";

    /// <summary>
    /// Gets the URL for a country flag image
    /// </summary>
    /// <param name="countryCode">ISO 2-letter country code (e.g., "NL", "US")</param>
    /// <returns>URL to the country flag PNG, or null if country code is empty</returns>
    public static string? GetCountryFlagUrl(string? countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode))
            return null;

        return $"{BaseUrl}/countries/{countryCode.ToLower()}.png";
    }

    /// <summary>
    /// Gets the URL for a cloud provider logo
    /// </summary>
    /// <param name="provider">Cloud provider name (e.g., "Azure", "AWS", "GCP")</param>
    /// <returns>URL to the cloud provider logo PNG, or null if provider is empty</returns>
    public static string? GetCloudProviderLogoUrl(string? provider)
    {
        if (string.IsNullOrWhiteSpace(provider))
            return null;

        return $"{BaseUrl}/cloud/{NormalizeProviderName(provider.ToLower())}.png";
    }
    
    private static string NormalizeProviderName(string provider)
    {
        if (provider.Contains("cloudflare", StringComparison.CurrentCultureIgnoreCase))
            return "cloudflare";
        
        return provider;
    }
}
