using System.Text.Json.Serialization;

namespace VulWall.Dashboard.Webhooks.Models;

public class ScanCompletedRequest
{
    [JsonPropertyName("scan_id")]
    public required string ScanId { get; init; }
}
