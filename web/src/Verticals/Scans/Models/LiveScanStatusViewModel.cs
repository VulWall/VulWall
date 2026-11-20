namespace VulWall.Dashboard.Scans.Models;

public class LiveScanStatusViewModel
{
    public bool IsScanning { get; set; }
    // Populated when IsScanning
    public string StartedTime { get; set; } = string.Empty;   // "02:31"
    public string Trigger { get; set; } = string.Empty;        // "manual · alex" or "automated"
    // Populated when !IsScanning
    public string NextScanCountdown { get; set; } = string.Empty; // "6d 4h" or ""
    public List<RecentRunViewModel> RecentRuns { get; set; } = new();
    public ScanNowState ScanNowState { get; set; }
}

public class RecentRunViewModel
{
    public string Date { get; set; } = string.Empty;           // "Now" or "MMM dd"
    public string ScanTypeLabel { get; set; } = string.Empty;  // "Scheduled" | "On-demand"
    public string ScanTypeIcon { get; set; } = string.Empty;   // "fa-clock" | "fa-bolt"
    public string StatusTone { get; set; } = string.Empty;     // "scanning" | "completed" | "failed" | "pending"
    public string Meta { get; set; } = string.Empty;           // "Scanning…" | "42 issues" | "Failed"
    public bool IsLive { get; set; }
}
