namespace VulWall.Dashboard.Scans.Models;

/// <summary>
/// What "Scan now" does: start a scan (Allowed), queue one to run right after the scan in
/// progress (InProgress), or nothing because a follow-up scan is already queued (Queued).
/// </summary>
public enum ScanNowState { Allowed, InProgress, Queued }
