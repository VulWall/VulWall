using MongoDB.Bson.Serialization.Attributes;

namespace VulWall.Dashboard.Data.Entities.Scan;

[BsonIgnoreExtraElements]
public class TargetedAsset
{
    [BsonElement("asset_id")]
    public string AssetId { get; set; } = null!;

    [BsonElement("type")]
    public string Type { get; set; } = null!;

    [BsonElement("value")]
    public string Value { get; set; } = null!;
}
