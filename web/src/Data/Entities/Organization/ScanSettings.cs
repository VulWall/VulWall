using MongoDB.Bson.Serialization.Attributes;

namespace VulWall.Dashboard.Data.Entities.Organization;

/// <summary>
/// Scan schedule for an organization (<c>organizations.scan_settings</c>). The scanner's scan
/// coordinator reads <c>scan_cron</c> and <c>enabled</c> as <c>shared.ScanSettings</c>; keep the
/// BSON names in sync with it.
/// </summary>
[BsonIgnoreExtraElements]
public class ScanSettings
{
    /// <summary>5-field cron in UTC.</summary>
    [BsonElement("scan_cron")]
    public string? ScanCron { get; set; }

    /// <summary>False turns scheduled scans off; the cron is kept so turning them on restores it.</summary>
    [BsonElement("enabled")]
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Time zone id the Settings form shows the schedule in. Web app only; the scanner ignores it.
    /// Null means UTC.
    /// </summary>
    [BsonElement("timezone")]
    [BsonIgnoreIfNull]
    public string? TimeZone { get; set; }

    /// <summary>The cron scheduled scans run on, or null when the schedule is off or empty.</summary>
    [BsonIgnore]
    public string? ActiveCron => Enabled && !string.IsNullOrWhiteSpace(ScanCron) ? ScanCron : null;
}
