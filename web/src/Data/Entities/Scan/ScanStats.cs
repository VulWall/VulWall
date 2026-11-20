using MongoDB.Bson.Serialization.Attributes;

namespace VulWall.Dashboard.Data.Entities.Scan;

[BsonIgnoreExtraElements]
public class ScanStats
{
    [BsonElement("total_assets")]
    public int TotalAssets { get; set; }

    [BsonElement("total_discoveries")]
    public int TotalDiscoveries { get; set; }

    [BsonElement("new_discoveries")]
    public int NewDiscoveries { get; set; }

    [BsonElement("resolved_discoveries")]
    public int ResolvedDiscoveries { get; set; }

    [BsonElement("total_findings")]
    public int TotalFindings { get; set; }

    [BsonElement("new_findings")]
    public int NewFindings { get; set; }

    [BsonElement("resolved_findings")]
    public int ResolvedFindings { get; set; }

    /// <summary>
    /// Open issues the scan did not see and kept open: it had no proof they are fixed (the check
    /// of their host did not run or did not complete, or the host was not found). Written by the scanner.
    /// </summary>
    [BsonElement("unchecked_findings")]
    public int UncheckedFindings { get; set; }
}
