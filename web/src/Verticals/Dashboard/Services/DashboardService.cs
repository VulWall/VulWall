using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services;
using VulWall.Dashboard.Common.Services.ScanTrigger;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Data.Entities.KnowledgeBase;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Extensions;
using VulWall.Dashboard.Common.Models;
using VulWall.Dashboard.Dashboard.Models;
using VulWall.Dashboard.Reports.Models;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Scans.Models;

namespace VulWall.Dashboard.Dashboard.Services;

public class DashboardService(
    AssetsRepository assetsRepository,
    FindingsRepository findingsRepository,
    ScansRepository scansRepository,
    DiscoveriesRepository discoveriesRepository,
    KnowledgeBaseCacheService knowledgeBaseCache,
    ISecurityScoreProvider securityScoreProvider,
    ISuppressionFilter suppressionFilter)
{
    public async Task<Models.IndexViewModel> GetIndexViewModelAsync()
    {
        // ── Fetch shared data once ──────────────────────────────────────
        var allFindingsTask = findingsRepository.GetAllAsync();
        var allDiscoveriesTask = discoveriesRepository.GetAllAsync();
        var doneScansTask = scansRepository.FindAsync(
            predicate: s => s.Status == ScanStatus.Done,
            orderByProperty: s => s.CreatedAt,
            sortDirection: SortDirection.Descending
        );
        var totalAssetsTask = assetsRepository.CountAsync(_ => true);
        var kbEntriesTask = knowledgeBaseCache.GetAllAsync();
        var suppressedKeysTask = suppressionFilter.GetActiveSuppressionKeysAsync();

        await Task.WhenAll(allFindingsTask, allDiscoveriesTask, doneScansTask, totalAssetsTask, kbEntriesTask, suppressedKeysTask);

        var suppressedKeys = await suppressedKeysTask;
        var allFindingsRaw = (await allFindingsTask).ToList();
        // Exclude actively-suppressed (discoveryId, findingType) pairs from open counts and score
        var allFindings = suppressionFilter.FilterSuppressed(allFindingsRaw, suppressedKeys).ToList();
        var allDiscoveries = (await allDiscoveriesTask).ToList();
        var doneScans = (await doneScansTask).ToList();
        var totalAssets = await totalAssetsTask;
        var kbEntries = await kbEntriesTask;

        var latestScan = doneScans.FirstOrDefault();
        var recentScans = doneScans.Take(5).ToList();

        // ── Stats from latest scan ──────────────────────────────────────
        var latestScanFindings = latestScan != null
            ? allFindings.Where(f => f.ScanIds.Contains(latestScan.Id)).ToList()
            : [];

        var (criticalIssues, highFindings, _, _) = FindingSeverityCounter.CountBySeverityGrouped(latestScanFindings);

        var discoveredAssets = latestScan != null
            ? allDiscoveries.Count(d =>
                d.OwnershipStatus == OwnershipStatus.Verified &&
                d.ScanIds != null &&
                d.ScanIds.Contains(latestScan.Id))
            : 0;

        // ── Security score (uses pre-fetched data) ──────────────────────
        var scoreResult = await securityScoreProvider.CalculateSecurityScoreAsync(
            allFindings, allDiscoveries, doneScans);

        // ── Fix Now section ─────────────────────────────────────────────
        var kbByType = kbEntries.ToDictionary(kb => kb.FindingType, kb => kb);

        var criticalHighFindings = latestScanFindings
            .Where(f => f.Severity == Severity.Critical || f.Severity == Severity.High)
            .OrderByDescending(f => f.FirstDetected)
            .ToList();

        var criticalVulnerabilities = criticalHighFindings
            .GroupBy(f => f.FindingType ?? f.Title)
            .Select(group =>
            {
                var firstFinding = group.First();
                var distinctDiscoveryIds = group
                    .Select(f => f.DiscoveryId)
                    .Where(id => !string.IsNullOrEmpty(id))
                    .Distinct()
                    .ToList();
                var affectedDiscoveryCount = distinctDiscoveryIds.Count;
                var findingsCount = group.Count();

                // One-click mute is only safe when the grouped finding resolves to exactly one
                // discovery; otherwise the user must choose which asset to mute on the detail page.
                var canOneClickMute = affectedDiscoveryCount == 1 && firstFinding.FindingType != null;

                var kb = firstFinding.FindingType != null && kbByType.TryGetValue(firstFinding.FindingType, out var entry) ? entry : null;
                var title = kb?.Business?.Title ?? firstFinding.Title;

                return new VulnerabilityItemViewModel
                {
                    Title = title,
                    Description = firstFinding.Description,
                    Severity = firstFinding.Severity.ToString(),
                    AffectedAssetsCount = affectedDiscoveryCount,
                    DiscoveryId = canOneClickMute ? distinctDiscoveryIds[0] : null,
                    CanOneClickMute = canOneClickMute,
                    FindingsCount = findingsCount,
                    DetailsUrl = $"/Recommendations/Detail/{firstFinding.Id}",
                    IsNew = group.Any(f => f.ScanIds.Count == 1),
                    IsExploitable = kb?.Metadata?.IsExploitable,
                    FindingType = firstFinding.FindingType,
                    OwaspCategory = kb?.Metadata?.OwaspCategory,
                    VulnerabilityExplanation = kb?.Technical?.VulnerabilityExplanation,
                    PotentialImpact = kb?.Technical?.Impact,
                    RemediationSteps = kb?.Technical?.RemediationSteps,
                    EstimatedEffort = kb?.Metadata?.EstimatedEffort,
                    Priority = kb?.Business?.Urgency,
                    LastDetected = group.Max(f => f.LastDetected)
                };
            })
            .OrderByDescending(v => GetSeverityOrder(v.Severity))
            .ThenByDescending(v => v.AffectedAssetsCount)
            .ThenBy(v => GetEffortOrder(v.EstimatedEffort))
            .ThenByDescending(v => v.LastDetected)
            .Take(3)
            .ToList();

        // ── Recent scans with findings lookup ───────────────────────────
        var recentScanIds = recentScans.Select(s => s.Id).ToHashSet();
        var findingsByScan = new Dictionary<string, List<Data.Entities.Finding.Finding>>();
        foreach (var scanId in recentScanIds)
            findingsByScan[scanId] = [];
        foreach (var finding in allFindings)
        {
            foreach (var scanId in finding.ScanIds)
            {
                if (findingsByScan.TryGetValue(scanId, out var list))
                    list.Add(finding);
            }
        }

        var recentScanViewModels = recentScans.Select(scan =>
        {
            var scanFindings = findingsByScan.GetValueOrDefault(scan.Id, []);

            var (criticalCount, highCount, mediumCount, lowCount) =
                FindingSeverityCounter.CountBySeverityGrouped(scanFindings);
            var totalIssues = criticalCount + highCount + mediumCount + lowCount;

            var severity = criticalCount > 0 ? "Critical" :
                highCount > 0 ? "High" :
                mediumCount > 0 ? "Medium" :
                lowCount > 0 ? "Low" : "Clean";

            var summary = totalIssues == 0 ? "No issues found" :
                totalIssues == 1 ? "1 issue" :
                $"{totalIssues} issues";

            return new RecentScanViewModel
            {
                AssetName = scan.TargetedAssets.FirstOrDefault()?.Value ?? "Unknown Asset",
                TimeAgo = scan.CreatedAt.ToRelativeTime(),
                Severity = severity,
                IssuesCount = totalIssues,
                Summary = summary,
                CriticalCount = criticalCount,
                HighCount = highCount,
                MediumCount = mediumCount,
                LowCount = lowCount
            };
        }).ToList();

        // ── Chart data & trends (use pre-fetched data) ──────────────────
        var chartData = await GetIssuesTimelineChartData(allFindings, doneScans, allDiscoveries);

        var (criticalTrend, highTrend, discoveredTrend) = CalculateStatsTrends(
            allFindings, doneScans, allDiscoveries,
            criticalIssues, highFindings, discoveredAssets);

        // ── Header + score hero context ─────────────────────────────────
        var scanNowState = await GetScanNowStateAsync();
        var primaryDomain = ResolvePrimaryDomain(allDiscoveries, latestScan);
        var scoreVerdict = ResolveScoreVerdict(scoreResult);

        var model = new Models.IndexViewModel
        {
            HasScanData = latestScan != null,
            PrimaryDomain = primaryDomain,
            LastScanTimeAgo = latestScan?.CreatedAt.ToRelativeTime() ?? "never",
            ScanNowState = scanNowState,
            ScoreBand = SecurityScoreCalculator.GetScoreLabel(scoreResult.Score),
            ScoreVerdict = scoreVerdict,
            TotalAssets = (int)totalAssets,
            CriticalIssues = criticalIssues,
            CriticalIssuesTrend = criticalTrend,
            HighIssues = highFindings,
            HighIssuesTrend = highTrend,
            DiscoveredAssets = (int)discoveredAssets,
            DiscoveredAssetsTrend = discoveredTrend,
            SecurityScore = scoreResult.Score,
            SecurityScoreTrend = scoreResult.Trend,
            SecurityScoreBreakdown = scoreResult.Breakdown,
            SecurityScoreSummary = scoreResult.Summary,
            SecurityScoreCap = scoreResult.AppliedCap,
            ChartData = chartData,
            CriticalVulnerabilities = criticalVulnerabilities,
            RecentScans = recentScanViewModels
        };

        return model;
    }

    /// <summary>
    /// Display-only state of the Overview "Rescan now" button, by the same rule as the Scans
    /// vertical. <c>ScansController.TriggerScan</c> goes through <c>ScanTriggerService</c>, which
    /// refuses server-side while a scan is in progress, so a stale value here can never start a second scan.
    /// </summary>
    private async Task<ScanNowState> GetScanNowStateAsync()
    {
        if (await scansRepository.ExistsAsync(s => s.Status == ScanStatus.Queued))
            return ScanNowState.Queued;

        return await scansRepository.ExistsAsync(ScanTriggerService.StartedPredicate(DateTime.UtcNow))
            ? ScanNowState.InProgress
            : ScanNowState.Allowed;
    }

    private static string ResolvePrimaryDomain(
        List<Data.Entities.Discovery.Discovery> allDiscoveries,
        Data.Entities.Scan.Scan? latestScan)
    {
        var rootDomain = allDiscoveries
            .Where(d => d.AssetType == AssetType.Domain && !string.IsNullOrWhiteSpace(d.Domain))
            .Select(d => d.Domain!)
            .FirstOrDefault();

        return rootDomain
               ?? latestScan?.TargetedAssets.FirstOrDefault()?.Value
               ?? "Your perimeter";
    }

    private static string ResolveScoreVerdict(SecurityScoreResult scoreResult)
    {
        // A cap reason is the binding constraint on the score, so it reads as the more
        // actionable verdict; fall back to the general summary explanation otherwise.
        if (!string.IsNullOrWhiteSpace(scoreResult.AppliedCap?.Reason))
            return scoreResult.AppliedCap!.Reason;

        return !string.IsNullOrWhiteSpace(scoreResult.Summary?.Explanation)
            ? scoreResult.Summary!.Explanation
            : string.Empty;
    }

    private static (int criticalTrend, int highTrend, int discoveredTrend) CalculateStatsTrends(
        List<Data.Entities.Finding.Finding> allFindings,
        List<Data.Entities.Scan.Scan> doneScans,
        List<Data.Entities.Discovery.Discovery> allDiscoveries,
        int currentCritical, int currentHigh, int currentDiscovered)
    {
        if (doneScans.Count < 2)
            return (0, 0, 0);

        var previousScan = doneScans[1]; // second most recent (list is already sorted desc)

        var previousFindings = allFindings
            .Where(f => f.ScanIds.Contains(previousScan.Id))
            .ToList();

        var (previousCritical, previousHigh, _, _) = FindingSeverityCounter.CountBySeverityGrouped(previousFindings);

        var previousDiscovered = allDiscoveries.Count(d =>
            d.OwnershipStatus == OwnershipStatus.Verified &&
            d.ScanIds != null &&
            d.ScanIds.Contains(previousScan.Id));

        return (
            currentCritical - previousCritical,
            currentHigh - previousHigh,
            currentDiscovered - previousDiscovered
        );
    }

    // Window cutoffs (days back from now) for the Overview trend toggle.
    private static readonly Dictionary<string, int> TimelineWindowDays = new()
    {
        ["30d"] = 30,
        ["90d"] = 90,
        ["6m"] = 180
    };

    private async Task<IssuesTimelineChartData> GetIssuesTimelineChartData(
        List<Data.Entities.Finding.Finding> allFindings,
        List<Data.Entities.Scan.Scan> doneScans,
        List<Data.Entities.Discovery.Discovery> allDiscoveries)
    {
        // doneScans comes in desc order; chart methods expect asc
        var scansList = doneScans.OrderBy(s => s.CreatedAt).ToList();
        var discoveryAssetTypes = allDiscoveries.ToDictionary(d => d.Id, d => d.AssetType);

        // Fetch assets once and share across all windows (avoids a DB read per window).
        var assetsList = (await assetsRepository.FindAsync(
            predicate: _ => true,
            orderByProperty: a => a.AddedOn,
            sortDirection: SortDirection.Ascending)).ToList();

        var now = DateTime.UtcNow;
        var ranges = new Dictionary<string, TimelineRange>();
        foreach (var (key, days) in TimelineWindowDays)
        {
            var cutoff = now.AddDays(-days);
            var windowScans = scansList.Where(s => s.CreatedAt >= cutoff).ToList();
            ranges[key] = BuildTimelineRange(allFindings, allDiscoveries, windowScans, assetsList, discoveryAssetTypes);
        }

        return new IssuesTimelineChartData { Ranges = ranges, DefaultRange = "90d" };
    }

    private TimelineRange BuildTimelineRange(
        List<Data.Entities.Finding.Finding> allFindings,
        List<Data.Entities.Discovery.Discovery> allDiscoveries,
        List<Data.Entities.Scan.Scan> windowScans,
        List<Data.Entities.Asset.Asset> assetsList,
        Dictionary<string, AssetType> discoveryAssetTypes)
    {
        var groupedData = GroupFindingsByScanDateAndSeverity(allFindings, windowScans);
        var monitoredAssetsData = GroupMonitoredAssetsByDate(windowScans, assetsList);
        var discoveriesData = GroupDiscoveriesByDate(allDiscoveries, windowScans);
        var securityScoreData = CalculateSecurityScoreByDate(allFindings, windowScans, discoveryAssetTypes);
        var scanStatsData = GroupScanStatsByDate(windowScans);

        return GenerateTimelineRange(groupedData, monitoredAssetsData, discoveriesData, securityScoreData, scanStatsData);
    }

    private static Dictionary<DateTime, Dictionary<Severity, int>> GroupFindingsByScanDateAndSeverity(
        List<Data.Entities.Finding.Finding> allFindings,
        List<Data.Entities.Scan.Scan> scans)
    {
        var grouped = new Dictionary<DateTime, Dictionary<Severity, int>>();
        var scansByDate = scans.GroupBy(s => s.CreatedAt.Date);

        foreach (var dateGroup in scansByDate)
        {
            var date = dateGroup.Key;
            var scansOnDate = dateGroup.ToList();

            // Collect all findings for scans on this date, then count grouped
            var scanIds = scansOnDate.Select(s => s.Id).ToHashSet();
            var dateFindings = allFindings.Where(f => f.ScanIds.Any(id => scanIds.Contains(id))).ToList();

            var (critical, high, medium, low) = FindingSeverityCounter.CountBySeverityGrouped(dateFindings);

            grouped[date] = new Dictionary<Severity, int>
            {
                { Severity.Critical, critical },
                { Severity.High, high },
                { Severity.Medium, medium },
                { Severity.Low, low }
            };
        }

        return grouped;
    }

    private static Dictionary<DateTime, int> GroupMonitoredAssetsByDate(
        List<Data.Entities.Scan.Scan> scans,
        List<Data.Entities.Asset.Asset> assetsList)
    {
        var grouped = new Dictionary<DateTime, int>();
        var scansByDate = scans.GroupBy(s => s.CreatedAt.Date);

        foreach (var dateGroup in scansByDate)
        {
            var date = dateGroup.Key;

            // Cumulative count of assets added on or before this scan date
            var assetsCount = assetsList.Count(a => a.AddedOn.Date <= date);
            grouped[date] = assetsCount;
        }

        return grouped;
    }

    private Dictionary<DateTime, int> GroupDiscoveriesByDate(
        List<Data.Entities.Discovery.Discovery> discoveries,
        List<Data.Entities.Scan.Scan> scans)
    {
        var grouped = new Dictionary<DateTime, int>();
        var scansByDate = scans.GroupBy(s => s.CreatedAt.Date);

        foreach (var dateGroup in scansByDate)
        {
            var date = dateGroup.Key;
            var scansOnDate = dateGroup.ToList();

            var discoveryIds = new HashSet<string>();
            foreach (var scan in scansOnDate)
            {
                var scanDiscoveries = discoveries.Where(d =>
                    d.ScanIds != null &&
                    d.ScanIds.Contains(scan.Id)
                );

                foreach (var discovery in scanDiscoveries)
                {
                    discoveryIds.Add(discovery.Id);
                }
            }

            grouped[date] = discoveryIds.Count;
        }

        return grouped;
    }

    private Dictionary<DateTime, ScanStats> GroupScanStatsByDate(List<Data.Entities.Scan.Scan> scans)
    {
        var grouped = new Dictionary<DateTime, ScanStats>();
        var scansByDate = scans.GroupBy(s => s.CreatedAt.Date);

        foreach (var dateGroup in scansByDate)
        {
            var date = dateGroup.Key;
            var latestScanOnDate = dateGroup.OrderByDescending(s => s.CreatedAt).First();
            grouped[date] = latestScanOnDate.Stats ?? new ScanStats();
        }

        return grouped;
    }

    private static Dictionary<DateTime, int> CalculateSecurityScoreByDate(
        List<Data.Entities.Finding.Finding> allFindings,
        List<Data.Entities.Scan.Scan> scans,
        Dictionary<string, AssetType> discoveryAssetTypes)
    {
        var scoreByDate = new Dictionary<DateTime, int>();
        var scansByDate = scans.GroupBy(s => s.CreatedAt.Date);

        foreach (var dateGroup in scansByDate)
        {
            var date = dateGroup.Key;
            var scansOnDate = dateGroup.ToList();

            // Get all findings from scans on this date
            var scanIds = scansOnDate.Select(s => s.Id).ToHashSet();
            var dateFindings = allFindings
                .Where(f => f.ScanIds.Any(id => scanIds.Contains(id)))
                .ToList();

            var groups = SecurityScoreCalculator.BuildFindingGroups(dateFindings, discoveryAssetTypes);
            scoreByDate[date] = SecurityScoreCalculator.CalculateScore(groups, date);
        }

        return scoreByDate;
    }

    private static TimelineRange GenerateTimelineRange(
        Dictionary<DateTime, Dictionary<Severity, int>> groupedData,
        Dictionary<DateTime, int> monitoredAssetsData,
        Dictionary<DateTime, int> discoveriesData,
        Dictionary<DateTime, int> securityScoreData,
        Dictionary<DateTime, ScanStats> scanStatsData)
    {
        var labels = new List<string>();
        var criticalSeries = new List<int>();
        var highSeries = new List<int>();
        var mediumSeries = new List<int>();
        var lowSeries = new List<int>();
        var scoreSeries = new List<int>();
        var monitoredAssetsSeries = new List<int>();
        var discoveriesSeries = new List<int>();
        var newFindingsSeries = new List<int>();
        var resolvedFindingsSeries = new List<int>();

        var allDates = new HashSet<DateTime>();
        allDates.UnionWith(groupedData.Keys);
        allDates.UnionWith(monitoredAssetsData.Keys);
        allDates.UnionWith(discoveriesData.Keys);
        allDates.UnionWith(securityScoreData.Keys);
        allDates.UnionWith(scanStatsData.Keys);

        foreach (var date in allDates.OrderBy(d => d))
        {
            var severities = groupedData.GetValueOrDefault(date);
            criticalSeries.Add(severities?.GetValueOrDefault(Severity.Critical) ?? 0);
            highSeries.Add(severities?.GetValueOrDefault(Severity.High) ?? 0);
            mediumSeries.Add(severities?.GetValueOrDefault(Severity.Medium) ?? 0);
            lowSeries.Add(severities?.GetValueOrDefault(Severity.Low) ?? 0);

            scoreSeries.Add(securityScoreData.GetValueOrDefault(date, 100));
            monitoredAssetsSeries.Add(monitoredAssetsData.GetValueOrDefault(date, 0));
            discoveriesSeries.Add(discoveriesData.GetValueOrDefault(date, 0));

            var scanStats = scanStatsData.GetValueOrDefault(date) ?? new ScanStats();
            newFindingsSeries.Add(scanStats.NewFindings);
            resolvedFindingsSeries.Add(scanStats.ResolvedFindings);

            labels.Add(date.ToString("MMM dd"));
        }

        return new TimelineRange(
            labels,
            criticalSeries,
            highSeries,
            mediumSeries,
            lowSeries,
            scoreSeries,
            monitoredAssetsSeries,
            discoveriesSeries,
            newFindingsSeries,
            resolvedFindingsSeries);
    }

    /// <summary>
    /// Returns sort order for severity (higher = more severe)
    /// </summary>
    private static int GetSeverityOrder(string severity) => severity.ToLower() switch
    {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0
    };

    /// <summary>
    /// Returns sort order for effort (lower = easier to fix)
    /// </summary>
    private static int GetEffortOrder(string? effort) => effort?.ToLower() switch
    {
        "trivial" => 1,
        "small" => 2,
        "medium" => 3,
        "large" => 4,
        _ => 5 // Unknown effort goes last
    };
}