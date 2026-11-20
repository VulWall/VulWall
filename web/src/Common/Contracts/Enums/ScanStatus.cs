namespace VulWall.Dashboard.Common.Contracts.Enums;

/// <summary>
/// Stored lowercase in <c>scans.status</c>. <c>queued</c> is written by the web app when the
/// user requests a scan; the scanner moves it to running and then to <c>done</c> or <c>failed</c>.
/// </summary>
public enum ScanStatus
{
    Queued,
    Pending,
    Running,
    Done,
    Failed
}
