using MongoDB.Bson.Serialization.Attributes;

namespace VulWall.Dashboard.Data.Entities.Organization;

public class SubscriptionSettings
{
    [BsonElement("max_assets")]
    public int MaxAssets { get; set; }

    [BsonElement("scan_cron")]
    public string? ScanCron { get; set; }
}