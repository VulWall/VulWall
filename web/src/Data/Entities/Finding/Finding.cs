using VulWall.Dashboard.Data.Abstractions;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using VulWall.Dashboard.Common.Contracts.Enums;

namespace VulWall.Dashboard.Data.Entities.Finding;

[BsonIgnoreExtraElements]
public class Finding : IEntity<string>, IOrganizationEntity
{
    [BsonId]
    [BsonElement("_id")]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [BsonElement("org_id")]
    public string OrgId { get; set; } = null!;

    [BsonElement("discovery_id")]
    public string? DiscoveryId { get; set; }

    [BsonElement("scan_ids")]
    public List<string> ScanIds { get; set; } = [];

    [BsonElement("severity")]
    public Severity Severity { get; set; }

    [BsonElement("title")]
    public string Title { get; set; } = string.Empty;

    [BsonElement("description")]
    public string Description { get; set; } = string.Empty;

    [BsonElement("finding_type")]
    public string? FindingType { get; set; }

    /// <summary>How to fix, when the scanner provides it (written by the scanner's ingestion).</summary>
    [BsonElement("remediation")]
    public string? Remediation { get; set; }

    /// <summary>Advisory and documentation URLs from the scanner.</summary>
    [BsonElement("references")]
    public List<string>? References { get; set; }

    [BsonElement("source")]
    public string? Source { get; set; }

    [BsonElement("status")]
    public string Status { get; set; } = "open";

    [BsonElement("first_detected")]
    public DateTime FirstDetected { get; set; }

    [BsonElement("last_detected")]
    public DateTime LastDetected { get; set; }

    // Metadata is a dynamic key-value document in MongoDB
    [BsonElement("metadata")]
    public BsonDocument? Metadata { get; set; }

}
