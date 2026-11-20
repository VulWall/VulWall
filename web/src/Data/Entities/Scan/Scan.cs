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

    /// <summary>How the scanner closed the scan: pipeline_quiescent, idle_timeout, safety_timeout or interrupted_by_restart.</summary>
    [BsonElement("completion_reason")]
    [BsonIgnoreIfNull]
    public string? CompletionReason { get; set; }

    /// <summary>
    /// True when the scan resolved the findings it did not see again. False for a partial scan
    /// (timeout, restart, DNS failures): its findings were left open. Null on older scans.
    /// </summary>
    [BsonElement("findings_reconciled")]
    [BsonIgnoreIfNull]
    public bool? FindingsReconciled { get; set; }

    /// <summary>Why the scanner judged the scan's view incomplete, e.g. "dns_failures".</summary>
    [BsonElement("degraded_reason")]
    [BsonIgnoreIfNull]
    public string? DegradedReason { get; set; }

    [BsonElement("targeted_assets")]
    public List<TargetedAsset> TargetedAssets { get; set; } = new();

    [BsonElement("stats")]
    public ScanStats Stats { get; set; } = new();

    [BsonElement("executive_summary")]
    [BsonIgnoreIfNull]
    public string? ExecutiveSummary { get; set; }
}
