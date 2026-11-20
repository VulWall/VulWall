using VulWall.Dashboard.Common.Models;

namespace VulWall.Dashboard.Reports.Models;

public class SummaryReportViewModel
{
    // Feature Access
    public FeatureAccess FeatureAccess { get; set; } = FeatureAccess.Free;

    // Header Information
    public string OrgId { get; set; } = string.Empty;
    public string OrganizationName { get; set; } = string.Empty;
    public string? LogoBase64 { get; set; }
    public DateTime ScanDate { get; set; }
    public string ReportId { get; set; } = string.Empty;
    public string SecurityPosture { get; set; } = string.Empty;
    public int SecurityScore { get; set; }

    // Executive Summary
    public string Overview { get; set; } = string.Empty;
    public string? AIExecutiveSummary { get; set; }
    public VulnerabilitySummary RiskSummary { get; set; } = new();
    public List<ImmediateAction> ImmediateActions { get; set; } = new();

    // Score trend over recent scans (oldest → newest), drives the verdict sparkline
    public List<ScoreTrendPoint> ScoreTrend { get; set; } = new();

    // Finding delta versus the previous scan, drives the verdict chips
    public FindingDelta FindingDelta { get; set; } = new();

    // Asset Discovery
    public List<string> RootDomains { get; set; } = new();
    public AssetDiscoveryStats AssetStats { get; set; } = new();
    public List<DiscoveredAsset> DiscoveredAssets { get; set; } = new();

    // Findings
    public List<Finding> CriticalFindings { get; set; } = new();
    public List<Finding> HighFindings { get; set; } = new();
    public List<Finding> MediumFindings { get; set; } = new();
    public List<Finding> LowFindings { get; set; } = new();


    // Technical Details
    public TechnicalScanDetails TechnicalDetails { get; set; } = new();

    // Remediation Roadmap
    public RemediationRoadmap Roadmap { get; set; } = new();

    // Scan Coverage
    public ScanCoverage Coverage { get; set; } = new();
}

public class VulnerabilitySummary
{
    public SeverityCount Critical { get; set; } = new();
    public SeverityCount High { get; set; } = new();
    public SeverityCount Medium { get; set; } = new();
    public SeverityCount Low { get; set; } = new();
    public SeverityCount Info { get; set; } = new();
}

/// <summary>A single point on the security-score trend line (one historical scan).</summary>
public record ScoreTrendPoint(DateTime Date, int Score);

/// <summary>New vs. resolved finding counts relative to the previous scan.</summary>
public record FindingDelta(int New, int Resolved, int NewAffectedAssets = 0)
{
    public FindingDelta() : this(0, 0, 0) { }
}

public class SeverityCount
{
    public int Count { get; set; }
    public int Exploitable { get; set; }
}

public class ImmediateAction
{
    public string Title { get; set; } = string.Empty;
    public string AffectedAsset { get; set; } = string.Empty;
}

public class AssetDiscoveryStats
{
    public int Domains { get; set; }
    public int NewDomains { get; set; }
    public int Subdomains { get; set; }
    public int NewSubdomains { get; set; }
    public int IPs { get; set; }
    public int NewIPs { get; set; }
    public int Ports { get; set; }
    public int NewPorts { get; set; }
    public int Services { get; set; }
    public int NewServices { get; set; }
}

public class DiscoveredAsset
{
    public string Subdomain { get; set; } = string.Empty;
    public string IP { get; set; } = string.Empty;
    public string CloudProvider { get; set; } = string.Empty;
    public List<string> Ports { get; set; } = new();
    public List<string> Services { get; set; } = new();
}

public class Finding
{
    public string Id { get; set; } = string.Empty;
    public string? FindingType { get; set; }
    public string Title { get; set; } = string.Empty;
    public string? SimplifiedTitle { get; set; }
    public string Severity { get; set; } = "low";
    public string? CvssScore { get; set; }
    public string? CweId { get; set; }
    public string? CveId { get; set; }
    public bool Exploitable { get; set; }
    public string Description { get; set; } = string.Empty;
    public List<string> AffectedAssets { get; set; } = new();
    public string? Risk { get; set; }
    public string? BusinessImpact { get; set; }
    public string? Evidence { get; set; }
    public string Remediation { get; set; } = string.Empty;
    public List<Reference> References { get; set; } = new();

    /// <summary>
    /// Returns simplified title if available, otherwise the original title
    /// </summary>
    public string DisplayTitle => SimplifiedTitle ?? Title;
}

public class Reference
{
    public string Url { get; set; } = string.Empty;
    public string Title { get; set; } = string.Empty;
}

public class RemediationRoadmap
{
    public List<RemediationItem> Immediate { get; set; } = new();
    public List<RemediationItem> ShortTerm { get; set; } = new();
    public List<RemediationItem> MediumTerm { get; set; } = new();
}

public class RemediationItem
{
    public string? FindingType { get; set; }
    public string Title { get; set; } = string.Empty;
    public string? AffectedAsset { get; set; }
    public int? AffectedAssetCount { get; set; }
    public string Impact { get; set; } = string.Empty;
    public string Effort { get; set; } = string.Empty;
}

public class TechnicalScanDetails
{
    public PassiveScan Passive { get; set; } = new();
    public ActiveScan Active { get; set; } = new();
}

public class PassiveScan
{
    public DateTime Start { get; set; }
    public DateTime End { get; set; }
    public List<string> Techniques { get; set; } = new();
    public PassiveScanResults Results { get; set; } = new();
}

public class PassiveScanResults
{
    public int Subdomains { get; set; }
    public int IPs { get; set; }
    public int CloudServices { get; set; }
}

public class ActiveScan
{
    public DateTime Start { get; set; }
    public DateTime End { get; set; }
    public string Frequency { get; set; } = string.Empty;
    public List<ScanTool> Tools { get; set; } = new();
}

public class ScanTool
{
    public string Name { get; set; } = string.Empty;
    public string Purpose { get; set; } = string.Empty;
    public string Results { get; set; } = string.Empty;
}

public class ScanCoverage
{
    public string Tier { get; set; } = string.Empty;
    public List<string> Exclusions { get; set; } = new();
    public ScanDepth Depth { get; set; } = new();
}

public class ScanDepth
{
}