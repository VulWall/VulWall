using MongoDB.Bson.Serialization.Attributes;

namespace VulWall.Dashboard.Data.Entities.Discovery;

public class ResolutionHistoryItem
{
    [BsonElement("ip")]
    public string Ip { get; set; } = null!;

    [BsonElement("first_seen")]
    public DateTime FirstSeen { get; set; }

    [BsonElement("last_seen")]
    public DateTime LastSeen { get; set; }
}