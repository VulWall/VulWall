using VulWall.Dashboard.Common.Services;
using VulWall.Dashboard.Data.Entities.KnowledgeBase;
using DbFinding = VulWall.Dashboard.Data.Entities.Finding.Finding;
using VulWall.Dashboard.Reports.Models;

namespace VulWall.Dashboard.Reports.Services.ReportGeneration;

public class TechnicalReportBuilder(
    SummaryReportBuilder summaryReportBuilder,
    KnowledgeBaseCacheService knowledgeBaseCache)
{
    public async Task<TechnicalReportViewModel> BuildReportAsync(
        string orgId,
        string organizationName,
        IEnumerable<DbFinding> findings,
        IEnumerable<Data.Entities.Discovery.Discovery> discoveries,
        Data.Entities.Scan.Scan? mostRecentScan,
        byte[]? logo = null,
        string? logoContentType = null)
    {
        // Build base summary report. The technical report does not render the score trend or
        // since-last-scan delta, so the trend/delta inputs are kept minimal (current scan only,
        // no previous scan to diff against).
        var findingsList = findings.ToList();
        var doneScans = mostRecentScan != null
            ? new List<Data.Entities.Scan.Scan> { mostRecentScan }
            : new List<Data.Entities.Scan.Scan>();

        var summaryReport = await summaryReportBuilder.BuildReportAsync(
            orgId,
            organizationName,
            findingsList,
            discoveries,
            mostRecentScan,
            doneScans,
            findingsList,
            null,
            null,
            logo,
            logoContentType
        );

        // Load KB entries for OWASP compliance mapping (only ~84 docs)
        var kbEntries = await knowledgeBaseCache.GetAllAsync();
        var kbByType = kbEntries.ToDictionary(kb => kb.FindingType, kb => kb);

        // Create technical report with all summary data plus technical-specific data
        var technicalReport = new TechnicalReportViewModel
        {
            // Copy all summary report properties
            OrganizationName = summaryReport.OrganizationName,
            LogoDataUri = summaryReport.LogoDataUri,
            ScanDate = summaryReport.ScanDate,
            ReportId = summaryReport.ReportId,
            SecurityPosture = summaryReport.SecurityPosture,
            SecurityScore = summaryReport.SecurityScore,
            Overview = summaryReport.Overview,
            RiskSummary = summaryReport.RiskSummary,
            ImmediateActions = summaryReport.ImmediateActions,
            RootDomains = summaryReport.RootDomains,
            AssetStats = summaryReport.AssetStats,
            DiscoveredAssets = summaryReport.DiscoveredAssets,
            CriticalFindings = summaryReport.CriticalFindings,
            HighFindings = summaryReport.HighFindings,
            MediumFindings = summaryReport.MediumFindings,
            LowFindings = summaryReport.LowFindings,
            Roadmap = summaryReport.Roadmap,
            TechnicalDetails = summaryReport.TechnicalDetails,
            Coverage = summaryReport.Coverage,

            // Add technical-specific data
            IpRanges = BuildIpRanges(),
            NotableServices = BuildNotableServices(discoveries.ToList()),
            OwaspCompliance = BuildOwaspCompliance(findings.ToList(), kbByType),
            TrendAnalysis = null // Not implemented yet
        };

        return technicalReport;
    }

    private List<IpRange> BuildIpRanges()
    {
        // Placeholder - will be populated when IP range tracking is implemented
        return new List<IpRange>();
    }

    private List<NotableService> BuildNotableServices(List<Data.Entities.Discovery.Discovery> discoveries)
    {
        return discoveries
            .Where(d => !string.IsNullOrEmpty(d.Service)
                     && !string.Equals(d.Service, "unknown", StringComparison.OrdinalIgnoreCase))
            .GroupBy(d => new { d.Service, d.Subdomain, d.Port })
            .Select(g =>
            {
                var first = g.First();
                var cloudProvider = GetCloudProviderFromMetadata(first.Metadata);
                return new NotableService
                {
                    ServiceName = g.Key.Service ?? "Unknown",
                    Host = g.Key.Subdomain ?? "Unknown",
                    Port = g.Key.Port?.ToString() ?? "N/A",
                    CloudProvider = cloudProvider ?? "Unknown",
                    Version = "N/A", // not tracked yet
                    Banner = "N/A"   // not tracked yet
                };
            })
            .OrderBy(svc => svc.ServiceName)
            .Take(10)
            .ToList();
    }

    private static string? GetCloudProviderFromMetadata(Dictionary<string, object?>? metadata)
    {
        if (metadata == null || !metadata.TryGetValue("cloud", out var cloudObj) || cloudObj == null)
            return null;

        if (cloudObj is IDictionary<string, object?> cloudDict &&
            cloudDict.TryGetValue("provider", out var provider) && provider != null)
            return provider.ToString();

        if (cloudObj is MongoDB.Bson.BsonDocument bsonDoc)
        {
            var val = bsonDoc.GetValue("provider", MongoDB.Bson.BsonNull.Value);
            return val.IsBsonNull ? null : val.AsString;
        }

        return null;
    }

    private static OwaspCompliance BuildOwaspCompliance(
        List<DbFinding> findings,
        Dictionary<string, KnowledgeBaseEntry> kbByType)
    {
        var owaspNames = new Dictionary<string, string>
        {
            ["A01"] = "Broken Access Control",
            ["A02"] = "Cryptographic Failures",
            ["A03"] = "Injection",
            ["A04"] = "Insecure Design",
            ["A05"] = "Security Misconfiguration",
            ["A06"] = "Vulnerable and Outdated Components",
            ["A07"] = "Identification and Authentication Failures",
            ["A08"] = "Software and Data Integrity Failures",
            ["A09"] = "Security Logging and Monitoring Failures",
            ["A10"] = "Server-Side Request Forgery"
        };

        // Static OWASP mapping by source for findings without KB-assigned category
        var sourceToOwasp = new Dictionary<string, string>
        {
            ["http-headers"] = "A05", // Security Misconfiguration
            ["testssl"] = "A02",      // Cryptographic Failures
            ["certificate"] = "A02",  // Cryptographic Failures
            ["jsscanner"] = "A06",    // Vulnerable and Outdated Components
            ["webtechprofiler"] = "A06", // Vulnerable and Outdated Components
            ["nuclei"] = "A05",       // Security Misconfiguration (fallback)
        };

        // Count findings per OWASP category: prefer KB-assigned, fall back to source mapping
        var countsByCategory = findings
            .Select(f =>
            {
                var kbOwasp = f.FindingType != null && kbByType.TryGetValue(f.FindingType, out var kb)
                    ? kb.Metadata?.OwaspCategory : null;
                return new
                {
                    Category = !string.IsNullOrEmpty(kbOwasp)
                        ? kbOwasp.ToUpper()
                        : (f.Source != null && sourceToOwasp.TryGetValue(f.Source, out var mapped) ? mapped : null)
                };
            })
            .Where(x => x.Category != null)
            .GroupBy(x => x.Category!)
            .ToDictionary(g => g.Key, g => g.Count());

        var owaspCategories = owaspNames.Select(kv =>
        {
            var count = countsByCategory.GetValueOrDefault(kv.Key, 0);
            return new OwaspCategory
            {
                Id = kv.Key,
                Name = kv.Value,
                Count = count,
                Status = DetermineStatus(count)
            };
        }).ToList();

        return new OwaspCompliance
        {
            Categories = owaspCategories
        };
    }

    private static string DetermineStatus(int count)
    {
        return count switch
        {
            0 => "Good",
            >= 1 and <= 2 => "Monitor",
            >= 3 and <= 5 => "Needs attention",
            _ => "Critical"
        };
    }
}
