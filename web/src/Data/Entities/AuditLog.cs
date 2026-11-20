using VulWall.Dashboard.Data.Abstractions;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
using VulWall.Dashboard.Common.Contracts.Enums;

namespace VulWall.Dashboard.Data.Entities;

public class AuditLog : IEntity<string>, IOrganizationEntity
{
    [BsonId]
    [BsonElement("_id")]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = ObjectId.GenerateNewId().ToString();

    /// <summary>
    /// Organization ID
    /// </summary>
    [BsonElement("org_id")]
    public string OrgId { get; set; } = string.Empty;

    /// <summary>
    /// Auth0 User ID (from claims)
    /// </summary>
    public string UserId { get; set; } = string.Empty;

    /// <summary>
    /// User's display name or email
    /// </summary>
    public string UserName { get; set; } = string.Empty;

    /// <summary>
    /// Category of the audit log (e.g., Account, Assets, Reports)
    /// </summary>
    public AuditLogCategory Category { get; set; }

    /// <summary>
    /// Action performed (e.g., "Generated", "Shared", "Downloaded", "Revoked")
    /// </summary>
    public string Action { get; set; } = string.Empty;

    /// <summary>
    /// Optional: Additional Info (e.g., "for example.com", "Monthly Report - August 2025")
    /// </summary>
    public string? AdditionalInfo { get; set; }

    /// <summary>
    /// IP Address of the user
    /// </summary>
    public string? IpAddress { get; set; }

    /// <summary>
    /// Whether this action was performed by a VulWall admin (e.g., during org switching).
    /// Admin actions are hidden from the customer-facing activity feed.
    /// </summary>
    [BsonElement("is_admin_action")]
    public bool IsAdminAction { get; set; }

    /// <summary>
    /// UTC timestamp when the action occurred
    /// </summary>
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}