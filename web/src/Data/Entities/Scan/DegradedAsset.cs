using MongoDB.Bson.Serialization.Attributes;

namespace VulWall.Dashboard.Data.Entities.Scan;

/// <summary>
/// A domain asset whose attack surface a scan could not fully see. Information for the user: the
/// scanner closes an issue only on proof that it is fixed, so issues it could not re-check stay
/// open. Written by the scanner (scans.degraded_assets).
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

    /// <summary>root_nxdomain, dns_failures, subdomain_enumeration_failed or publish_failed.</summary>
    [BsonElement("reason")]
    public string Reason { get; set; } = string.Empty;
}
