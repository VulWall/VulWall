using VulWall.Dashboard.Data.Abstractions;
using MongoDB.Bson.Serialization.Attributes;

namespace VulWall.Dashboard.Data.Entities.FindingSuppression;

[BsonIgnoreExtraElements]
public class FindingSuppression : IEntity<string>, IOrganizationEntity
{
    [BsonId]
    [BsonElement("_id")]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [BsonElement("org_id")]
    public string OrgId { get; set; } = null!;

    [BsonElement("discovery_id")]
    public string DiscoveryId { get; set; } = null!;

    [BsonElement("finding_type")]
    public string FindingType { get; set; } = null!;

    /// <summary>
    /// Suppression reason: "false_positive" or "accepted_risk".
    /// Use <see cref="SuppressionStatus"/> constants.
    /// </summary>
    [BsonElement("status")]
    public string Status { get; set; } = null!;

    /// <summary>
    /// Optional note explaining why this was suppressed.
    /// </summary>
    [BsonElement("note")]
    public string? Note { get; set; }

    /// <summary>
    /// Auth0 user ID or email of the user who performed the suppression.
    /// </summary>
    [BsonElement("suppressed_by")]
    public string SuppressedBy { get; set; } = null!;

    [BsonElement("suppressed_at")]
    public DateTime SuppressedAt { get; set; }

    /// <summary>
    /// When false the suppression is deactivated (history is preserved).
    /// </summary>
    [BsonElement("active")]
    public bool Active { get; set; } = true;
}
