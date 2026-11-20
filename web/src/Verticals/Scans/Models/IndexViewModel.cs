namespace VulWall.Dashboard.Scans.Models;

public class IndexViewModel
{
    public int TotalScans { get; set; }
    public ScanOverviewStatistics Statistics { get; set; } = new();
    public List<ScanStatistics> HeatmapData { get; set; } = new();
    public List<string> ScheduledScanDates { get; set; } = new();

    /// <summary>
    /// Pre-computed diff of the two most recent Done scans. Null when fewer than 2 Done scans exist.
    /// </summary>
    public ScanComparisonViewModel? InitialComparison { get; set; }

    public LiveScanStatusViewModel LiveScanStatus { get; set; } = new();

    /// <summary>
    /// Drives the "Scan Now" button rendering: whether the current org can trigger an on-demand scan.
    /// </summary>
    public ScanNowState ScanNowState { get; set; }

    /// <summary>
    /// Timestamp (UTC) of the most recent scan, regardless of status. Null when no scans exist.
    /// </summary>
    public DateTime? LastScanAt { get; set; }
}

public class ScanStatistics
{
    public string ScanId { get; set; } = string.Empty;
    public string Date { get; set; } = string.Empty;
    public string ScanType { get; set; } = string.Empty;
    public int Critical { get; set; }
    public int High { get; set; }
    public int Medium { get; set; }
    public int Low { get; set; }
}
