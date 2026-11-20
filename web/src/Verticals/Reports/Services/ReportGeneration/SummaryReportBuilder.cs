using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services;
using VulWall.Dashboard.Common.Services.Mappers;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Data.Entities.KnowledgeBase;
using DbFinding = VulWall.Dashboard.Data.Entities.Finding.Finding;
using VulWall.Dashboard.Reports.Models;

namespace VulWall.Dashboard.Reports.Services.ReportGeneration;

public class SummaryReportBuilder
{
    private readonly FindingsAggregator _findingsAggregator;
    private readonly VulnerabilitySummaryBuilder _vulnerabilitySummaryBuilder;
    private readonly KnowledgeBaseCacheService _knowledgeBaseCache;
    private readonly ScoreHistoryBuilder _scoreHistoryBuilder;
    private readonly FindingDeltaBuilder _findingDeltaBuilder;

    // Number of recent completed scans to include in the score-trend sparkline.
    private const int ScoreTrendWindow = 6;

    public SummaryReportBuilder(
        FindingsAggregator findingsAggregator,
        VulnerabilitySummaryBuilder vulnerabilitySummaryBuilder,
        KnowledgeBaseCacheService knowledgeBaseCache,
        ScoreHistoryBuilder scoreHistoryBuilder,
        FindingDeltaBuilder findingDeltaBuilder)
    {
        _findingsAggregator = findingsAggregator;
        _vulnerabilitySummaryBuilder = vulnerabilitySummaryBuilder;
        _knowledgeBaseCache = knowledgeBaseCache;
        _scoreHistoryBuilder = scoreHistoryBuilder;
        _findingDeltaBuilder = findingDeltaBuilder;
    }

    public async Task<SummaryReportViewModel> BuildReportAsync(
        string orgId,
        string organizationName,
        IEnumerable<DbFinding> findings,
        IEnumerable<Data.Entities.Discovery.Discovery> discoveries,
        Data.Entities.Scan.Scan? mostRecentScan,
        IEnumerable<Data.Entities.Scan.Scan> allDoneScans,
        IEnumerable<DbFinding> allFindings,
        string? previousScanId,
        IEnumerable<Data.Entities.Discovery.Discovery>? allDiscoveries = null,
        byte[]? logo = null)
    {
        var findingsList = findings.ToList();
        var discoveriesList = discoveries.ToList();
        var allFindingsList = allFindings.ToList();
        // Use org-wide discoveries for asset-type weighting in the trend; fall back to scan-scoped.
        var allDiscoveriesList = (allDiscoveries ?? discoveries).ToList();

        // Last N completed scans, oldest → newest, for the trend sparkline.
        var trendScans = allDoneScans
            .Where(s => s.Status == ScanStatus.Done)
            .OrderByDescending(s => s.CreatedAt)
            .Take(ScoreTrendWindow)
            .OrderBy(s => s.CreatedAt)
            .ToList();

        var scoreTrend = _scoreHistoryBuilder.Build(trendScans, allFindingsList, allDiscoveriesList);
        var findingDelta = _findingDeltaBuilder.Build(mostRecentScan?.Id, previousScanId, allFindingsList);

        // Load KB entries for enrichment (only ~84 docs)
        var kbEntries = await _knowledgeBaseCache.GetAllAsync();
        var kbByType = kbEntries.ToDictionary(kb => kb.FindingType, kb => kb);

        var scanDate = mostRecentScan?.CreatedAt ?? DateTime.UtcNow;

        // Calculate security score using the same algorithm as the dashboard
        var discoveryAssetTypes = discoveriesList.ToDictionary(d => d.Id, d => d.AssetType);
        var findingGroups = SecurityScoreCalculator.BuildFindingGroups(findingsList, discoveryAssetTypes);
        var scoreResult = SecurityScoreCalculator.Calculate(findingGroups, DateTime.UtcNow);
        var securityPosture = scoreResult.Summary.Status;
        var securityScore = scoreResult.Score;

        var aiExecutiveSummary = mostRecentScan?.ExecutiveSummary;

        return new SummaryReportViewModel
        {
            // Header
            OrgId = orgId,
            OrganizationName = organizationName,
            LogoBase64 = logo != null ? Convert.ToBase64String(logo) : null,
            ScanDate = scanDate,
            ReportId = $"VW-{DateTime.UtcNow:yyyy-MM}-{Guid.NewGuid().ToString()[..3].ToUpper()}",
            SecurityPosture = securityPosture,
            SecurityScore = securityScore,

            // Executive Summary
            Overview = $"This report presents findings from VulWall's automated external security assessment of {organizationName}'s internet-facing infrastructure. The assessment was conducted through unauthenticated scanning from external vantage points, simulating the perspective of an external attacker.",
            AIExecutiveSummary = aiExecutiveSummary,
            RiskSummary = BuildVulnerabilitySummary(findingsList, kbByType),
            ImmediateActions = BuildImmediateActions(findingsList, kbByType),
            ScoreTrend = scoreTrend,
            FindingDelta = findingDelta,

            // Asset Discovery
            RootDomains = BuildRootDomains(discoveriesList),
            AssetStats = BuildAssetStats(discoveriesList, scanDate),
            DiscoveredAssets = BuildDiscoveredAssets(discoveriesList),

            // Findings
            CriticalFindings = BuildFindings(findingsList, Severity.Critical, kbByType),
            HighFindings = BuildFindings(findingsList, Severity.High, kbByType),
            MediumFindings = BuildFindings(findingsList, Severity.Medium, kbByType),
            LowFindings = BuildFindings(findingsList, Severity.Low, kbByType),

            // Remediation Roadmap
            Roadmap = BuildRemediationRoadmap(findingsList, kbByType, discoveriesList),

            // Technical Details
            TechnicalDetails = BuildTechnicalDetails(discoveriesList, findingsList, mostRecentScan),

            // Scan Coverage
            Coverage = BuildScanCoverage()
        };
    }

    private VulnerabilitySummary BuildVulnerabilitySummary(
        List<DbFinding> findings,
        Dictionary<string, KnowledgeBaseEntry> kbByType)
    {
        var summary = _vulnerabilitySummaryBuilder.BuildSummary(findings, kbByType);

        return new VulnerabilitySummary
        {
            Critical = new SeverityCount
            {
                Count = summary["critical_count"],
                Exploitable = summary["critical_exploitable"]
            },
            High = new SeverityCount
            {
                Count = summary["high_count"],
                Exploitable = summary["high_exploitable"]
            },
            Medium = new SeverityCount
            {
                Count = summary["medium_count"],
                Exploitable = summary["medium_exploitable"]
            },
            Low = new SeverityCount
            {
                Count = summary["low_count"],
                Exploitable = summary["low_exploitable"]
            },
            Info = new SeverityCount
            {
                Count = summary["info_count"],
                Exploitable = summary["info_exploitable"]
            }
        };
    }

    private List<ImmediateAction> BuildImmediateActions(
        List<DbFinding> findings,
        Dictionary<string, KnowledgeBaseEntry> kbByType)
    {
        var criticalAndHigh = _findingsAggregator.GetCriticalAndHighFindings(findings, kbByType);

        return criticalAndHigh.Select(f => new ImmediateAction
        {
            Title = f["title"].ToString() ?? "",
            AffectedAsset = f["affected_asset"].ToString() ?? ""
        }).ToList();
    }

    private List<string> BuildRootDomains(List<Data.Entities.Discovery.Discovery> discoveries)
    {
        return discoveries
            .Where(d => d.AssetType == AssetType.Domain)
            .Select(d => d.Domain ?? "unknown")
            .Distinct()
            .ToList();
    }

    private AssetDiscoveryStats BuildAssetStats(List<Data.Entities.Discovery.Discovery> discoveries, DateTime scanStartDate)
    {
        return new AssetDiscoveryStats
        {
            Domains = discoveries.Count(d => d.AssetType == AssetType.Domain),
            NewDomains = discoveries.Count(d => d.AssetType == AssetType.Domain && d.FirstSeen >= scanStartDate),
            Subdomains = discoveries.Count(d => d.AssetType == AssetType.SubDomain),
            NewSubdomains = discoveries.Count(d => d.AssetType == AssetType.SubDomain && d.FirstSeen >= scanStartDate),
            IPs = discoveries.Count(d => d.AssetType == AssetType.Ip),
            NewIPs = discoveries.Count(d => d.AssetType == AssetType.Ip && d.FirstSeen >= scanStartDate),
            Ports = discoveries.Count(d => d.AssetType == AssetType.Port),
            NewPorts = discoveries.Count(d => d.AssetType == AssetType.Port && d.FirstSeen >= scanStartDate),
            Services = 0, // Not tracked separately yet
            NewServices = 0
        };
    }

    private List<DiscoveredAsset> BuildDiscoveredAssets(List<Data.Entities.Discovery.Discovery> discoveries)
    {
        var subdomains = discoveries.Where(d => d.AssetType == AssetType.SubDomain).ToList();
        var ipsByParent = discoveries
            .Where(d => d.AssetType == AssetType.Ip && !string.IsNullOrEmpty(d.ParentId))
            .GroupBy(d => d.ParentId!)
            .ToDictionary(g => g.Key, g => g.ToList());
        var portsByParent = discoveries
            .Where(d => d.AssetType == AssetType.Port && !string.IsNullOrEmpty(d.ParentId))
            .GroupBy(d => d.ParentId!)
            .ToDictionary(g => g.Key, g => g.ToList());
        // Keyed by IP string for fallback lookup when subdomain has no direct child IP record
        var ipDiscoveryByAddress = discoveries
            .Where(d => d.AssetType == AssetType.Ip && !string.IsNullOrEmpty(d.Ip))
            .GroupBy(d => d.Ip!)
            .ToDictionary(g => g.Key, g => g.First());

        return subdomains.Select(d =>
        {
            // Get child IP records for this subdomain
            var childIps = ipsByParent.GetValueOrDefault(d.Id, []);

            // Get IP from child IP discovery records, fall back to resolution_history on the subdomain
            var ip = childIps
                .OrderByDescending(ipRec => ipRec.LastSeen)
                .FirstOrDefault()
                ?.Ip
                ?? d.ResolutionHistory?.OrderByDescending(r => r.FirstSeen).FirstOrDefault()?.Ip;

            // Cloud enrichment may live on the subdomain itself or on a child IP record
            var cloudProvider = GetCloudProviderFromMetadata(d.Metadata)
                             ?? GetCloudProviderFromMetadata(childIps.FirstOrDefault()?.Metadata);

            // Get ports via direct child IPs; if none, look up the shared IP record by address
            var fallbackIpRecord = childIps.Count == 0 && ip != null
                ? ipDiscoveryByAddress.GetValueOrDefault(ip)
                : null;
            var ports = childIps.Count > 0
                ? childIps.SelectMany(ipRec => portsByParent.GetValueOrDefault(ipRec.Id, [])).ToList()
                : fallbackIpRecord != null
                    ? portsByParent.GetValueOrDefault(fallbackIpRecord.Id, [])
                    : [];

            var portNumbers = ports
                .Where(p => p.Port.HasValue)
                .Select(p => p.Port!.Value.ToString())
                .Distinct()
                .ToList();

            var services = ports
                .Where(p => !string.IsNullOrEmpty(p.Service) && p.Service != "unknown")
                .Select(p => p.Service!)
                .Distinct()
                .ToList();

            return new DiscoveredAsset
            {
                Subdomain = d.Subdomain ?? d.Domain ?? "unknown",
                IP = ip ?? "N/A",
                CloudProvider = cloudProvider ?? "Unknown",
                Ports = portNumbers,
                Services = services
            };
        }).ToList();
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

    private List<Models.Finding> BuildFindings(
        List<DbFinding> findings,
        Severity severity,
        Dictionary<string, KnowledgeBaseEntry> kbByType)
    {
        var detailedFindings = _findingsAggregator.GetDetailedFindings(findings, severity);
        var findingsById = findings.ToDictionary(f => f.Id, f => f);

        var mapped = detailedFindings.Select(f =>
        {
            var findingId = f["finding_id"].ToString() ?? "";
            var originalFinding = findingsById.GetValueOrDefault(findingId);
            var kb = originalFinding?.FindingType != null && kbByType.TryGetValue(originalFinding.FindingType, out var entry) ? entry : null;

            return new Models.Finding
            {
                Id = findingId,
                FindingType = originalFinding?.FindingType,
                Title = f["title"].ToString() ?? "",
                SimplifiedTitle = kb?.Business?.Title,
                Severity = severity.ToString().ToLower(),
                CvssScore = f.ContainsKey("cvss_score") ? f["cvss_score"]?.ToString() : null,
                CweId = f.ContainsKey("cwe_id") ? f["cwe_id"]?.ToString() : null,
                CveId = f.ContainsKey("cve_id") ? f["cve_id"]?.ToString() : null,
                Exploitable = kb?.Metadata?.IsExploitable == true,
                Description = f["description"].ToString() ?? "",
                AffectedAssets = BuildAffectedAssets(f),
                Risk = kb?.Technical?.Impact
                       ?? (f.ContainsKey("risk_explanation") ? f["risk_explanation"]?.ToString() : null),
                BusinessImpact = BusinessImpactMapper.GetBusinessImpact(originalFinding?.FindingType),
                Evidence = f.ContainsKey("technical_evidence") ? f["technical_evidence"]?.ToString() : null,
                Remediation = BuildRemediationText(kb),
                References = BuildReferences(f)
            };
        }).ToList();

        // Group by finding type so the same issue on 20 assets = 1 card with 20 affected assets listed,
        // not 20 identical rows. Merge exploitable (true wins). Evidence/remediation stay representative
        // (first finding's), while CveId/CweId are merged across the group so distinct identifiers are
        // not silently dropped.
        return mapped
            .GroupBy(f => f.FindingType ?? f.DisplayTitle)
            .Select(g =>
            {
                var first = g.First();
                return new Models.Finding
                {
                    Id = first.Id,
                    FindingType = first.FindingType,
                    Title = first.Title,
                    SimplifiedTitle = first.SimplifiedTitle,
                    Severity = first.Severity,
                    CvssScore = first.CvssScore,
                    CweId = string.Join(", ", g.Select(f => f.CweId).Where(v => !string.IsNullOrEmpty(v)).Distinct()),
                    CveId = string.Join(", ", g.Select(f => f.CveId).Where(v => !string.IsNullOrEmpty(v)).Distinct()),
                    Exploitable = g.Any(f => f.Exploitable),
                    Description = first.Description,
                    AffectedAssets = g.SelectMany(f => f.AffectedAssets).Distinct().ToList(),
                    Risk = first.Risk,
                    BusinessImpact = first.BusinessImpact,
                    Evidence = first.Evidence,
                    Remediation = first.Remediation,
                    References = first.References
                };
            })
            .ToList();
    }

    private static string BuildRemediationText(KnowledgeBaseEntry? kb)
    {
        var steps = kb?.Technical?.RemediationSteps;
        if (steps?.Any() == true)
        {
            return string.Join("\n", steps.Select((step, i) => $"{i + 1}. {step}"));
        }

        return string.Empty;
    }

    private List<string> BuildAffectedAssets(Dictionary<string, object> finding)
    {
        if (!finding.ContainsKey("affected_assets"))
            return new List<string>();

        var assets = finding["affected_assets"];

        if (assets is IEnumerable<Dictionary<string, string>> assetList)
        {
            return assetList.Select(a => a.ContainsKey("asset_url") ? a["asset_url"] : "Unknown").ToList();
        }

        return new List<string>();
    }

    private List<Reference> BuildReferences(Dictionary<string, object> finding)
    {
        if (!finding.ContainsKey("references"))
            return new List<Reference>();

        var refs = finding["references"];

        if (refs is IEnumerable<Dictionary<string, string>> refList)
        {
            return refList.Select(r => new Reference
            {
                Url = r.ContainsKey("reference_url") ? r["reference_url"] : "",
                Title = r.ContainsKey("reference_url") ? r["reference_url"] : ""
            }).ToList();
        }

        return new List<Reference>();
    }

    private static RemediationRoadmap BuildRemediationRoadmap(
        List<DbFinding> findings,
        Dictionary<string, KnowledgeBaseEntry> kbByType,
        List<Data.Entities.Discovery.Discovery> discoveries)
    {
        var discoveryDict = discoveries.ToDictionary(d => d.Id, d => d);

        var groups = findings
            .Where(f => f.Status == "open")
            .GroupBy(f => new { FindingType = f.FindingType ?? f.Title, f.Severity })
            .Select(g =>
            {
                var first = g.First();
                var key = first.FindingType;
                var kb = key != null && kbByType.TryGetValue(key, out var entry) ? entry : null;

                var title = kb?.Business?.Title
                    ?? (first.Source == "testssl"
                        ? TestSSLTitleMapper.MapTitle(first.FindingType, first.Title)
                        : first.Title);
                var impact = g.Key.Severity switch
                {
                    Severity.Critical or Severity.High => "high",
                    Severity.Medium => "medium",
                    _ => "low"
                };
                var effort = kb?.Metadata?.EstimatedEffort ?? string.Empty;
                var urgency = kb?.Business?.Urgency;
                var count = g.Count();

                var primaryDiscoveryId = first.DiscoveryId;
                string? primaryAsset = null;
                if (primaryDiscoveryId != null && discoveryDict.TryGetValue(primaryDiscoveryId, out var disc))
                    primaryAsset = disc.Subdomain ?? disc.Domain;

                return new
                {
                    Severity = g.Key.Severity,
                    Urgency = urgency,
                    Count = count,
                    Item = new RemediationItem
                    {
                        FindingType = key,
                        Title = title,
                        AffectedAsset = primaryAsset ?? "Unknown",
                        AffectedAssetCount = count,
                        Impact = impact,
                        Effort = effort
                    }
                };
            })
            .ToList();

        var immediate = new List<(Severity Severity, RemediationItem Item)>();
        var shortTerm = new List<(Severity Severity, RemediationItem Item)>();
        var mediumTerm = new List<(Severity Severity, RemediationItem Item)>();

        foreach (var g in groups)
        {
            var bucket = g.Urgency switch
            {
                "immediate" => immediate,
                "high" => shortTerm,
                "medium" => mediumTerm,
                "low" => mediumTerm,
                _ => g.Severity switch
                {
                    Severity.Critical or Severity.High => immediate,
                    Severity.Medium => shortTerm,
                    _ => mediumTerm
                }
            };
            bucket.Add((g.Severity, g.Item));
        }

        static List<RemediationItem> Sort(List<(Severity Severity, RemediationItem Item)> list) =>
            list.OrderByDescending(x => x.Severity)
                .ThenByDescending(x => x.Item.AffectedAssetCount)
                .Select(x => x.Item)
                .ToList();

        return new RemediationRoadmap
        {
            Immediate = Sort(immediate),
            ShortTerm = Sort(shortTerm),
            MediumTerm = Sort(mediumTerm)
        };
    }

    private static readonly Dictionary<string, (string DisplayName, string Purpose)> _sourceMeta = new(StringComparer.OrdinalIgnoreCase)
    {
        ["nuclei"]           = ("Nuclei",            "Vulnerability scanning"),
        ["testssl"]          = ("testssl",            "TLS / cipher inspection"),
        ["jsscanner"]        = ("JS Scanner",         "JavaScript dependency scanning"),
        ["webtechprofiler"]  = ("WebTech Profiler",   "Web technology profiling"),
        ["http-headers"]     = ("HTTP Headers",       "HTTP security header analysis"),
        ["email-security"]   = ("Email Security",     "SPF / DKIM / DMARC checks"),
    };

    private static TechnicalScanDetails BuildTechnicalDetails(
        List<Data.Entities.Discovery.Discovery> discoveries,
        List<DbFinding> findings,
        Data.Entities.Scan.Scan? mostRecentScan)
    {
        var scanStart = mostRecentScan?.CreatedAt ?? DateTime.UtcNow;
        var scanEnd   = mostRecentScan?.CompletedAt ?? scanStart;
        var portCount = discoveries.Count(d => d.AssetType == AssetType.Port);

        var tools = findings
            .Where(f => f.Source != null && _sourceMeta.ContainsKey(f.Source))
            .GroupBy(f => f.Source!, StringComparer.OrdinalIgnoreCase)
            .OrderByDescending(g => g.Count())
            .Select(g =>
            {
                var (name, purpose) = _sourceMeta[g.Key];
                var count = g.Count();
                var results = g.Key.Equals("nuclei", StringComparison.OrdinalIgnoreCase)
                    ? $"{count} findings / {portCount} ports"
                    : $"{count} findings";
                return new ScanTool { Name = name, Purpose = purpose, Results = results };
            })
            .ToList();

        // Fallback: if no findings present, show Nuclei as placeholder
        if (!tools.Any())
            tools.Add(new ScanTool { Name = "Nuclei", Purpose = "Vulnerability scanning", Results = "0 findings" });

        return new TechnicalScanDetails
        {
            Passive = new PassiveScan
            {
                Start      = scanStart,
                End        = scanEnd,
                Techniques = new List<string> { "Subdomain enumeration", "DNS enumeration", "Certificate transparency" },
                Results    = new PassiveScanResults
                {
                    Subdomains     = discoveries.Count(d => d.AssetType == AssetType.SubDomain),
                    IPs            = discoveries.Count(d => d.AssetType == AssetType.Ip),
                    CloudServices  = discoveries.Count(d => GetCloudProviderFromMetadata(d.Metadata) != null)
                }
            },
            Active = new ActiveScan
            {
                Start     = scanStart,
                End       = scanEnd,
                Frequency = "Scheduled",
                Tools     = tools
            }
        };
    }

    private static ScanCoverage BuildScanCoverage()
    {
        return new ScanCoverage
        {
            Exclusions = new List<string>
            {
                "Internal network infrastructure",
                "Authenticated application testing",
                "Social engineering vectors",
                "Physical security assessment"
            },
            Depth = new ScanDepth()
        };
    }

}
