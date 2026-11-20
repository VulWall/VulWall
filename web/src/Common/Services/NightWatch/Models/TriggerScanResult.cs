namespace VulWall.Dashboard.Common.Services.NightWatch.Models;

/// <summary>
/// Outcome of a scan trigger request to NightWatch.
/// </summary>
public enum TriggerScanOutcome
{
    Started,
    AlreadyRunning,
    Failed
}

public sealed record TriggerScanResult(TriggerScanOutcome Outcome, string? ScanId = null)
{
    public static readonly TriggerScanResult AlreadyRunning = new(TriggerScanOutcome.AlreadyRunning);
    public static readonly TriggerScanResult Failed = new(TriggerScanOutcome.Failed);
}
