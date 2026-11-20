using VulWall.Dashboard.Data.Abstractions;
using MongoDB.Bson.Serialization.Attributes;
using VulWall.Dashboard.Common.Contracts.Enums;

namespace VulWall.Dashboard.Data.Entities.Scan;

[BsonIgnoreExtraElements]
public class Scan : IEntity<string>, IOrganizationEntity
{
    [BsonId]
    [BsonElement("_id")]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [BsonElement("org_id")]
    public string OrgId { get; set; } = null!;

    [BsonElement("status")]
    public ScanStatus Status { get; set; }

    [BsonElement("type")]
    public ScanType Type { get; set; }

    [BsonElement("triggered_by")]
    public string TriggeredBy { get; set; } = null!;

    [BsonElement("created_at")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [BsonElement("updated_at")]
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    [BsonElement("completed_at")]
    public DateTime? CompletedAt { get; set; }

    [BsonElement("targeted_assets")]
    public List<TargetedAsset> TargetedAssets { get; set; } = new();

    [BsonElement("stats")]
    public ScanStats Stats { get; set; } = new();

    [BsonElement("executive_summary")]
    public string? ExecutiveSummary { get; set; }
}
