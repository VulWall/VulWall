using MongoDB.Bson.Serialization.Attributes;

namespace VulWall.Dashboard.Data.Entities.Organization;

/// <summary>
/// Scan schedule for an organization. The element name and <c>scan_cron</c> field are read by
/// the scanner's scan coordinator and must not be renamed.
/// </summary>
[BsonIgnoreExtraElements] // older documents also carry max_assets
public class SubscriptionSettings
{
    [BsonElement("scan_cron")]
    public string? ScanCron { get; set; }
}
