namespace VulWall.Dashboard.Scans.Models;

public class ScanComparisonViewModel
{
    public string BaselineScanId { get; set; } = string.Empty;
    public string LatestScanId   { get; set; } = string.Empty;
    public string BaselineDate   { get; set; } = string.Empty;  // "Apr 26, 2026"
    public string LatestDate     { get; set; } = string.Empty;  // "Jun 14, 2026"
    public string BaselineTime   { get; set; } = string.Empty;  // "02:31 · automated"
    public string LatestTime     { get; set; } = string.Empty;
    public int    BaselineTotal  { get; set; }
    public int    LatestTotal    { get; set; }
    public int    Net            { get; set; }   // latestTotal - baselineTotal (negative = improved)
    public int    PctChange      { get; set; }   // abs % change
    public bool   Improved       { get; set; }   // Net < 0
    public bool   NoChange       { get; set; }   // Net == 0

    public List<SeverityBandDelta> Bands     { get; set; } = new();
    public List<DiffFinding>       Resolved  { get; set; } = new();  // capped at 6
    public List<DiffFinding>       Added     { get; set; } = new();  // capped at 6
    public int ResolvedTotal     { get; set; }   // total count before cap
    public int AddedTotal        { get; set; }
    public int UnchangedCount    { get; set; }
}

public class SeverityBandDelta
{
    public string Name    { get; set; } = string.Empty;
    public int    From    { get; set; }
    public int    To      { get; set; }
    public int    Delta   { get; set; }   // To - From (negative = improved)
    public bool   Worsened { get; set; }  // Delta > 0
}

public class DiffFinding
{
    public string Severity { get; set; } = string.Empty;  // "Critical","High","Medium","Low"
    public string Title    { get; set; } = string.Empty;
    public string Host     { get; set; } = string.Empty;  // Finding.Source ?? ""
}
