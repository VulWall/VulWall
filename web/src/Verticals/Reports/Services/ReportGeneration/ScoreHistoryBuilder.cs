using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Reports.Models;
using DbDiscovery = VulWall.Dashboard.Data.Entities.Discovery.Discovery;
using DbFinding = VulWall.Dashboard.Data.Entities.Finding.Finding;
using DbScan = VulWall.Dashboard.Data.Entities.Scan.Scan;

namespace VulWall.Dashboard.Reports.Services.ReportGeneration;

/// <summary>
/// Recomputes the security score for each of a handful of recent completed scans so the
/// summary report can render a score-trend sparkline. The score for a scan is derived only
/// from the findings that participated in that scan, using the same scoring algorithm as the
/// live dashboard (<see cref="SecurityScoreCalculator"/>).
/// </summary>
public class ScoreHistoryBuilder
{
    /// <summary>
    /// Builds the trend series in ascending chronological order (oldest scan first).
    /// </summary>
    /// <param name="orderedDoneScansAscending">Completed scans, oldest → newest (already trimmed to the desired window).</param>
    /// <param name="allFindings">All suppression-filtered findings across every scan.</param>
    /// <param name="allDiscoveries">All discoveries, used to weight findings by asset type.</param>
    public List<ScoreTrendPoint> Build(
        IReadOnlyList<DbScan> orderedDoneScansAscending,
        IReadOnlyList<DbFinding> allFindings,
        IReadOnlyList<DbDiscovery> allDiscoveries)
    {
        // Discovery IDs are unique, but guard against accidental duplicates defensively.
        var discoveryAssetTypes = allDiscoveries
            .GroupBy(d => d.Id)
            .ToDictionary(g => g.Key, g => g.First().AssetType);

        var referenceTime = DateTime.UtcNow;
        var points = new List<ScoreTrendPoint>(orderedDoneScansAscending.Count);

        foreach (var scan in orderedDoneScansAscending)
        {
            var scanFindings = allFindings.Where(f => f.ScanIds.Contains(scan.Id)).ToList();
            var groups = SecurityScoreCalculator.BuildFindingGroups(scanFindings, discoveryAssetTypes);
            var score = SecurityScoreCalculator.Calculate(groups, referenceTime).Score;

            points.Add(new ScoreTrendPoint(scan.CompletedAt ?? scan.CreatedAt, score));
        }

        return points;
    }
}
