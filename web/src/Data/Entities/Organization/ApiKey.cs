using MongoDB.Bson.Serialization.Attributes;

namespace VulWall.Dashboard.Data.Entities.Organization;

public class ApiKey
{
    [BsonElement("key")]
    public string Key { get; set; } = null!;

    [BsonElement("created_at")]
    public DateTime CreatedAt { get; set; }

    [BsonElement("expires_at")]
    public DateTime? ExpiresAt { get; set; }
}
