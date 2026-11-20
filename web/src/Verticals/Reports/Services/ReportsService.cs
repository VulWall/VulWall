using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Reports.Models;
using DbScan = VulWall.Dashboard.Data.Entities.Scan.Scan;
using DbFinding = VulWall.Dashboard.Data.Entities.Finding.Finding;
using DbDiscovery = VulWall.Dashboard.Data.Entities.Discovery.Discovery;

namespace VulWall.Dashboard.Reports.Services;

public class ReportsService
{
    /// <summary>
    /// Builds the per-scan selector items shown on the Reports index page. Each item carries the
    /// scan's findings/asset counts, severity breakdown, and the same security score + band the
    /// dashboard and reports use, so the page can render a scan-scoped context strip without an
    /// extra round trip. Findings are expected to be already suppression-filtered by the caller.
    /// </summary>
    public Task<List<ScanSelectItem>> BuildScanSelectItemsAsync(
        IEnumerable<DbScan> scans,
        List<DbFinding> allFindings,
        IEnumerable<DbDiscovery> allDiscoveries)
    {
        // Index findings/discoveries by scan id once so the per-scan loop is O(S + F + D)
        // instead of re-scanning every finding/discovery for each scan.
        var findingsByScan = GroupByScanId(allFindings, f => f.ScanIds);
        var discoveriesByScan = GroupByScanId(allDiscoveries, d => d.ScanIds);

        var items = scans
            .Where(s => s.Status == ScanStatus.Done)
            .OrderByDescending(s => s.CreatedAt)
            .Select(scan => BuildScanSelectItem(
                scan,
                findingsByScan.GetValueOrDefault(scan.Id, []),
                discoveriesByScan.GetValueOrDefault(scan.Id, [])))
            .ToList();

        return Task.FromResult(items);
    }

    private static Dictionary<string, List<T>> GroupByScanId<T>(
        IEnumerable<T> items, Func<T, List<string>?> scanIdsSelector)
    {
        var lookup = new Dictionary<string, List<T>>();
        foreach (var item in items)
        {
            var scanIds = scanIdsSelector(item);
            if (scanIds == null) continue;

            foreach (var scanId in scanIds)
            {
                if (!lookup.TryGetValue(scanId, out var bucket))
                {
                    bucket = [];
                    lookup[scanId] = bucket;
                }
                bucket.Add(item);
            }
        }
        return lookup;
    }

    private static ScanSelectItem BuildScanSelectItem(
        DbScan scan,
        List<DbFinding> scanFindings,
        List<DbDiscovery> scanDiscoveries)
    {
        // Same scoring path as SummaryReportBuilder so the band matches everywhere.
        var discoveryAssetTypes = scanDiscoveries.ToDictionary(d => d.Id, d => d.AssetType);
        var findingGroups = SecurityScoreCalculator.BuildFindingGroups(scanFindings, discoveryAssetTypes);
        var scoreResult = SecurityScoreCalculator.Calculate(findingGroups, DateTime.UtcNow);

        return new ScanSelectItem
        {
            Id = scan.Id,
            DisplayName = $"{scan.Type} Scan - {scan.CreatedAt:MMM dd, yyyy}",
            CreatedAt = scan.CreatedAt,
            FindingsCount = scanFindings.Count,
            AssetsCount = scanDiscoveries.Count,
            Score = scoreResult.Score,
            Band = scoreResult.Summary.Status,
            Critical = scanFindings.Count(f => f.Severity == Severity.Critical),
            High = scanFindings.Count(f => f.Severity == Severity.High),
            Medium = scanFindings.Count(f => f.Severity == Severity.Medium),
            Low = scanFindings.Count(f => f.Severity == Severity.Low),
            Info = scanFindings.Count(f => f.Severity == Severity.Info)
        };
    }

}
