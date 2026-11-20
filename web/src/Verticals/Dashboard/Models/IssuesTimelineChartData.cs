namespace VulWall.Dashboard.Dashboard.Models;

/// <summary>
/// One pre-computed time window of the Overview trend chart. The Overview page
/// renders three windows (30d / 90d / 6m) and the client toggles between them
/// without a round-trip, so each window ships its own fully-formed series.
/// </summary>
public record TimelineRange(
    List<string> Labels,
    List<int> Critical,
    List<int> High,
    List<int> Medium,
    List<int> Low,
    List<int> SecurityScore,
    List<int> MonitoredAssets,
    List<int> Discoveries,
    List<int> NewFindings,
    List<int> ResolvedFindings
);

public class IssuesTimelineChartData
{
    /// <summary>Keyed by window: "30d", "90d", "6m".</summary>
    public Dictionary<string, TimelineRange> Ranges { get; init; } = new();

    public string DefaultRange { get; init; } = "90d";
}
