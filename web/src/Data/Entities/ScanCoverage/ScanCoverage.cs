using VulWall.Dashboard.Data.Abstractions;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace VulWall.Dashboard.Data.Entities.ScanCoverage;

/// <summary>
/// A scanner coverage record (scan_coverage). The scanner owns the other fields; the web app
/// maps only what it needs to find an asset's records.
/// </summary>
[BsonIgnoreExtraElements]
public class ScanCoverage : IEntity<string>, IOrganizationEntity
{
    // The scanner upserts without an _id, so MongoDB assigns an ObjectId.
    [BsonId]
    [BsonElement("_id")]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = null!;

    [BsonElement("org_id")]
    public string OrgId { get; set; } = null!;

    [BsonElement("discovery_id")]
    public string DiscoveryId { get; set; } = null!;
}
