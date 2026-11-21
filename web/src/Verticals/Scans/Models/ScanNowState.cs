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
    /// A scan queued behind a running one. The web app refuses "Scan now" during a scan, so this
    /// is normally the scanner's scheduled scan (the schedule fired during the scan). Neutral
    /// wording, because a requested scan can still end up queued behind a stuck running scan.
    /// </summary>
    public const string QueuedAfterCurrent = "Another scan will start after the current one.";
}
