using MongoDB.Bson.Serialization.Attributes;
using VulWall.Dashboard.Data.Abstractions;

namespace VulWall.Dashboard.Data.Entities.SharedLink;

public class SharedLink : IEntity<string>, IOrganizationEntity
{
    [BsonId]
    [BsonElement("_id")]
    public string Id { get; set; } = Guid.NewGuid().ToString();

    [BsonElement("org_id")]
    public string OrgId { get; set; } = null!;

    [BsonElement("token")]
    public string Token { get; set; } = Guid.NewGuid().ToString("N");

    [BsonElement("scan_id")]
    public string ScanId { get; set; } = null!;

    [BsonElement("report_name")]
    public string ReportName { get; set; } = null!;

    [BsonElement("password_hash")]
    public string PasswordHash { get; set; } = null!;

    [BsonElement("created_at")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [BsonElement("expiration_days")]
    public int ExpirationDays { get; set; }

    [BsonElement("is_revoked")]
    public bool IsRevoked { get; set; }

    [BsonIgnore]
    public DateTime ExpiresAt => CreatedAt.AddDays(ExpirationDays);

    [BsonIgnore]
    public bool IsExpired => DateTime.UtcNow > ExpiresAt;

    [BsonIgnore]
    public bool IsActive => !IsRevoked && !IsExpired;
}
