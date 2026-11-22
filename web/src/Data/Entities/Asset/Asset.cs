using VulWall.Dashboard.Data.Abstractions;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using VulWall.Dashboard.Common.Contracts.Enums;

namespace VulWall.Dashboard.Data.Entities.Asset;

// Older documents carry dns_verified_at from the removed DNS ownership check.
[BsonIgnoreExtraElements]
public class Asset : IEntity<string>, IOrganizationEntity
{
    [BsonId]
    [BsonElement("_id")]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = ObjectId.GenerateNewId().ToString();

    [BsonElement("org_id")]
    public string OrgId { get; set; } = null!;

    [BsonElement("type")]
    public AssetType Type { get; set; }

    [BsonElement("enabled")]
    public bool Enabled { get; set; }

    // Set when a delete starts (AssetsService.DeleteAssetAsync) and never cleared: the asset can
    // then only be deleted again, not enabled or disabled, and the scanner neither scans it nor
    // records it on discoveries. Missing on assets no delete has touched.
    [BsonElement("deleting")]
    [BsonIgnoreIfDefault]
    public bool Deleting { get; set; }

    [BsonElement("domain")]
    [BsonIgnoreIfNull]
    public string? Domain { get; set; }

    [BsonElement("ip")]
    [BsonIgnoreIfNull]
    public string? Ip { get; set; }

    [BsonElement("added_on")]
    public DateTime AddedOn { get; set; } = DateTime.UtcNow;
}