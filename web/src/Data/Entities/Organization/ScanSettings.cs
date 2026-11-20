using MongoDB.Bson.Serialization.Attributes;

namespace VulWall.Dashboard.Data.Entities.Organization;

/// <summary>
/// Scan schedule for an organization (<c>organizations.scan_settings</c>). The scanner's scan
/// coordinator reads it as <c>shared.ScanSettings</c>; keep the BSON names in sync with it.
/// </summary>
[BsonIgnoreExtraElements]
public class ScanSettings
{
    [BsonElement("scan_cron")]
    public string? ScanCron { get; set; }
}
