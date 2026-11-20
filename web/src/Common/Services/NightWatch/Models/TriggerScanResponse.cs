using System.Text.Json.Serialization;

namespace VulWall.Dashboard.Common.Services.NightWatch.Models;

public class TriggerScanResponse
{
    [JsonPropertyName("scan_id")]
    public string? ScanId { get; init; }
}
