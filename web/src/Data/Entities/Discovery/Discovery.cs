using VulWall.Dashboard.Data.Abstractions;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using VulWall.Dashboard.Common.Contracts.Enums;

namespace VulWall.Dashboard.Data.Entities.Discovery;

[BsonIgnoreExtraElements]
public class Discovery : IEntity<string>, IOrganizationEntity
{
    [BsonId]
    [BsonElement("_id")]
    [BsonRepresentation(BsonType.String)]
    public string Id { get; set; } = null!;

    [BsonElement("org_id")]
    public string OrgId { get; set; } = null!;

    [BsonElement("asset_type")]
    public AssetType AssetType { get; set; }

    [BsonElement("source")]
    public string Source { get; set; } = null!;

    [BsonElement("status")]
    public AssetStatus Status { get; set; }

    [BsonElement("ownership_status")]
    public OwnershipStatus OwnershipStatus { get; set; }

    [BsonElement("discovered_at")]
    public DateTime DiscoveredAt { get; set; }

    [BsonElement("first_seen")]
    public DateTime FirstSeen { get; set; }

    [BsonElement("last_seen")]
    public DateTime LastSeen { get; set; }

    [BsonElement("scan_ids")]
    public List<string>? ScanIds { get; set; }

    [BsonElement("parent_id")]
    public string? ParentId { get; set; }

    [BsonElement("metadata")]
    public Dictionary<string, object?>? Metadata { get; set; }

    [BsonElement("domain")]
    public string? Domain { get; set; }

    [BsonElement("subdomain")]
    public string? Subdomain { get; set; }
    
    [BsonElement("protocol")]
    public string? Protocol { get; set; }
    
    [BsonElement("port")]
    public int? Port { get; set; }
    
    [BsonElement("service_name")]
    public string? Service { get; set; }

    [BsonElement("ip")]
    public string? Ip { get; set; }

    [BsonElement("resolution_history")]
    public List<ResolutionHistoryItem>? ResolutionHistory { get; set; }
}