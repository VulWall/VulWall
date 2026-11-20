using VulWall.Dashboard.Data.Abstractions;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace VulWall.Dashboard.Data.Entities;

/// <summary>
/// Records that an organization was deleted.
/// Intentionally stores no PII — only the org_id and the timestamp.
/// Retained for compliance and audit purposes even after the org is gone.
/// </summary>
public class DeletionLog : IEntity<string>
{
    [BsonId]
    [BsonElement("_id")]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; } = ObjectId.GenerateNewId().ToString();

    [BsonElement("org_id")]
    public string OrgId { get; set; } = string.Empty;

    [BsonElement("deleted_at")]
    public DateTime DeletedAt { get; set; } = DateTime.UtcNow;
}
