namespace VulWall.Dashboard.Reports.Models;

// Technical report extends Summary report with additional technical details and compliance
public class TechnicalReportViewModel : SummaryReportViewModel
{
    // IP Ranges — always empty; NightWatch emits no CIDR/ASN/PTR data yet
    public List<IpRange> IpRanges { get; set; } = new();

    // Notable Services
    public List<NotableService> NotableServices { get; set; } = new();

    // OWASP Top 10 Compliance
    public OwaspCompliance OwaspCompliance { get; set; } = new();

    // Trend Analysis — reserved; trends collection is global threat-intel, not per-org delta
    public TrendAnalysis? TrendAnalysis { get; set; }
}

// IpRange fields are schema-ready but always empty — NightWatch emits no CIDR/ASN/PTR enrichment yet
public class IpRange
{
    public string CidrRange { get; set; } = string.Empty;
    public string CloudProvider { get; set; } = string.Empty;
    public string Asn { get; set; } = string.Empty;
    public string PtrRecords { get; set; } = string.Empty;
}

public class NotableService
{
    public string ServiceName { get; set; } = string.Empty;
    public string Host { get; set; } = string.Empty;
    public string Port { get; set; } = string.Empty;
    public string CloudProvider { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty; // not tracked yet — always "N/A"
    public string Banner { get; set; } = string.Empty;  // not tracked yet — always "N/A"
}

public class OwaspCompliance
{
    public List<OwaspCategory> Categories { get; set; } = new();
}

public class OwaspCategory
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public int Count { get; set; }
    public string Status { get; set; } = string.Empty;
}

public class TrendAnalysis
{
    public TrendMetrics Previous { get; set; } = new();
    public TrendMetrics Current { get; set; } = new();
    public int NewAssets { get; set; }
    public int ResolvedIssues { get; set; }
    public bool Improved { get; set; }
    public string Summary { get; set; } = string.Empty;
}

public class TrendMetrics
{
    public int Total { get; set; }
    public int CriticalHigh { get; set; }
}
