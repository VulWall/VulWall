using System.Text.Json.Serialization;

namespace VulWall.Dashboard.Common.Services.NightWatch.Models;

public class TriggerScanRequest
{
    [JsonPropertyName("org_id")]
    public required string OrgId { get; init; }

    [JsonPropertyName("triggered_by")]
    public required string TriggeredBy { get; init; }
}
