using MongoDB.Bson.Serialization.Attributes;
using VulWall.Dashboard.Data.Abstractions;

namespace VulWall.Dashboard.Data.Entities.SystemInfo;

/// <summary>
/// The scanner's versions, written by the scanner (system_info, _id "scanner") at start-up and every
/// few minutes. The web app only reads it. An empty or missing value means not known.
/// </summary>
[BsonIgnoreExtraElements]
public class ScannerSystemInfo : IEntity<string>
{
    public const string ScannerId = "scanner";

    [BsonId]
    public string Id { get; set; } = ScannerId;

    [BsonElement("version")] public string? Version { get; set; }
    [BsonElement("nuclei")] public string? Nuclei { get; set; }
    [BsonElement("nuclei_templates")] public string? NucleiTemplates { get; set; }
    [BsonElement("nuclei_templates_updated_at")] public DateTime? NucleiTemplatesUpdatedAt { get; set; }
    [BsonElement("testssl")] public string? TestSsl { get; set; }
    [BsonElement("retire")] public string? Retire { get; set; }
    [BsonElement("dbip_country_date")] public string? DbIpCountryDate { get; set; }
    [BsonElement("dbip_asn_date")] public string? DbIpAsnDate { get; set; }
    [BsonElement("started_at")] public DateTime? StartedAt { get; set; }
    [BsonElement("updated_at")] public DateTime? UpdatedAt { get; set; }
}
