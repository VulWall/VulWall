namespace VulWall.Dashboard.Discoveries.Models;

/// <summary>
/// Geographic and hosting information extracted from discovery metadata
/// </summary>
public class DiscoveryGeoInfo
{
    public string? CountryCode { get; set; }
    public string? Continent { get; set; }
    public string? Isp { get; set; }
    public string? CloudProvider { get; set; }
    public string? CloudRegion { get; set; }
    public string? Waf { get; set; }

    /// <summary>
    /// The CDN whose shared edge this IP is (metadata.cdn_edge, set by the scanner). The scanner
    /// runs nuclei on the names behind it, not on the address.
    /// </summary>
    public string? CdnEdge { get; set; }

    public static DiscoveryGeoInfo FromMetadata(Dictionary<string, object?>? metadata)
    {
        var geoInfo = new DiscoveryGeoInfo();

        if (metadata == null || metadata.Count == 0)
            return geoInfo;

        try
        {
            // Extract geo data
            if (metadata.TryGetValue("geo", out var geoObj) && geoObj != null)
            {
                var geoDict = geoObj as IDictionary<string, object?> ??
                              geoObj as System.Dynamic.ExpandoObject;

                if (geoDict != null)
                {
                    if (geoDict.TryGetValue("country", out var country))
                        geoInfo.CountryCode = country?.ToString();

                    if (geoDict.TryGetValue("continent", out var continent))
                        geoInfo.Continent = continent?.ToString();

                    if (geoDict.TryGetValue("isp", out var isp))
                        geoInfo.Isp = isp?.ToString();
                }
            }

            // Extract cloud data
            if (metadata.TryGetValue("cloud", out var cloudObj) && cloudObj != null)
            {
                var cloudDict = cloudObj as IDictionary<string, object?> ?? cloudObj as System.Dynamic.ExpandoObject;

                if (cloudDict != null)
                {
                    if (cloudDict.TryGetValue("provider", out var provider))
                        geoInfo.CloudProvider = provider?.ToString();

                    if (cloudDict.TryGetValue("region", out var region))
                        geoInfo.CloudRegion = region?.ToString();
                }
            }

            // Extract WAF
            if (metadata.TryGetValue("waf", out var waf))
                geoInfo.Waf = waf?.ToString();

            if (metadata.TryGetValue("cdn_edge", out var cdnEdge))
                geoInfo.CdnEdge = cdnEdge?.ToString();
        }
        catch
        {
            // Return empty geo info on any parsing errors
        }

        return geoInfo;
    }
}