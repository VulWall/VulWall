namespace VulWall.Dashboard.Scans.Models;

/// <summary>
/// What "Scan now" can do: start a scan (Allowed), or nothing because a scan is running
/// (InProgress) or queued (Queued). A queued scan is one that waits for the scanner, or one the
/// scanner queued because the schedule fired during a running scan.
/// </summary>
public enum ScanNowState
{
    Allowed,
    InProgress,
    Queued
}

public static class ScanNowStateText
{
    /// <summary>
    /// A scan queued behind a running one. The web app never queues one there, only the scanner
    /// does, when the schedule fires during a scan, so it is a scheduled scan.
    /// </summary>
    public const string QueuedAfterCurrent = "A scheduled scan will start after the current one.";
}
