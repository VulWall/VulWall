using VulWall.Dashboard.Data.Abstractions;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using VulWall.Dashboard.Common.Contracts.Enums;

namespace VulWall.Dashboard.Data.Entities.Asset;

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

    [BsonElement("dns_verified_at")]
    public DateTime? DnsVerifiedAt { get; set; }

    [BsonElement("domain")]
    [BsonIgnoreIfNull]
    public string? Domain { get; set; }

    [BsonElement("ip")]
    [BsonIgnoreIfNull]
    public string? Ip { get; set; }

    [BsonElement("added_on")]
    public DateTime AddedOn { get; set; } = DateTime.UtcNow;
}