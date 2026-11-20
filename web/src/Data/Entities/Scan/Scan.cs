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
    [BsonIgnoreIfNull]
    public DateTime? CompletedAt { get; set; }

    /// <summary>Why a failed scan failed, e.g. <see cref="InterruptedByRestart"/>. Written by the scanner.</summary>
    [BsonElement("status_reason")]
    [BsonIgnoreIfNull]
    public string? StatusReason { get; set; }

    /// <summary>The scanner restarted while this scan ran; it was closed as failed and resolved no findings.</summary>
    public const string InterruptedByRestart = "interrupted_by_restart";

    [BsonElement("targeted_assets")]
    public List<TargetedAsset> TargetedAssets { get; set; } = new();

    [BsonElement("stats")]
    public ScanStats Stats { get; set; } = new();

    [BsonElement("executive_summary")]
    [BsonIgnoreIfNull]
    public string? ExecutiveSummary { get; set; }
}
