using MongoDB.Bson.Serialization.Attributes;

namespace VulWall.Dashboard.Data.Entities.Scan;

/// <summary>
/// A domain asset whose attack surface a scan could not fully see. The scan left the findings
/// under it open. Written by the scanner (scans.degraded_assets).
/// </summary>
[BsonIgnoreExtraElements]
public class DegradedAsset
{
    /// <summary>The domain does not exist (NXDOMAIN, confirmed by public resolvers).</summary>
    public const string RootNxDomain = "root_nxdomain";

    /// <summary>assets._id; empty for scans from older scanner versions.</summary>
    [BsonElement("asset_id")]
    [BsonIgnoreIfNull]
    public string? AssetId { get; set; }

    [BsonElement("domain")]
    public string Domain { get; set; } = string.Empty;

    /// <summary>root_nxdomain, dns_failures or subdomain_enumeration_failed.</summary>
    [BsonElement("reason")]
    public string Reason { get; set; } = string.Empty;
}
