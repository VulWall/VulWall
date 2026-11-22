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

    /// <summary>
    /// When the scanner started the scan. Written by the scanner when it claims a queued scan
    /// (which keeps its original <see cref="CreatedAt"/>) or inserts a scheduled one. Null on
    /// queued scans and on scans from older scanner versions.
    /// </summary>
    [BsonElement("started_at")]
    [BsonIgnoreIfNull]
    public DateTime? StartedAt { get; set; }

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
    /// True when the scan's pipeline drained and every asset was fully checked. False for a partial
    /// scan: a timeout close (nothing resolved), or a scan with <see cref="DegradedAssets"/>. Null on
    /// older scans. Either way, the scanner closes an issue only on proof that it is fixed.
    /// </summary>
    [BsonElement("findings_reconciled")]
    [BsonIgnoreIfNull]
    public bool? FindingsReconciled { get; set; }

    /// <summary>Domain assets this scan could not fully check. Written by the scanner.</summary>
    [BsonElement("degraded_assets")]
    public List<DegradedAsset> DegradedAssets { get; set; } = [];

    /// <summary>Open findings this scan did not see and left open because it had no proof they are fixed.</summary>
    [BsonElement("unchecked_finding_ids")]
    public List<string> UncheckedFindingIds { get; set; } = [];

    private HashSet<string>? _uncheckedFindingIdSet;

    /// <summary>
    /// <see cref="UncheckedFindingIds"/> as a set for per-finding lookups, built on first use.
    /// The web app reads scans and never changes this list, so the set does not go stale.
    /// </summary>
    [BsonIgnore]
    public IReadOnlySet<string> UncheckedFindingIdSet => _uncheckedFindingIdSet ??= [.. UncheckedFindingIds];

    /// <summary>Number of distinct assets in <see cref="DegradedAssets"/>.</summary>
    public int DegradedAssetCount() =>
        DegradedAssets.Select(a => string.IsNullOrEmpty(a.AssetId) ? a.Domain : a.AssetId).Distinct().Count();

    [BsonElement("targeted_assets")]
    public List<TargetedAsset> TargetedAssets { get; set; } = new();

    [BsonElement("stats")]
    public ScanStats Stats { get; set; } = new();

    [BsonElement("executive_summary")]
    [BsonIgnoreIfNull]
    public string? ExecutiveSummary { get; set; }
}
