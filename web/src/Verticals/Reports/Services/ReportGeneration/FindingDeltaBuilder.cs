using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Reports.Models;
using DbFinding = VulWall.Dashboard.Data.Entities.Finding.Finding;

namespace VulWall.Dashboard.Reports.Services.ReportGeneration;

/// <summary>
/// Computes how the finding set changed between the current scan and the previous one.
/// A finding entity accumulates the IDs of every scan it appeared in, so membership of a
/// scan is determined by whether that scan's ID is present in the finding's <c>ScanIds</c>.
/// A finding that one of the two scans did not check is neither new nor resolved
/// (<see cref="ScanCheck"/>), the same rule as the scan comparison.
/// </summary>
public class FindingDeltaBuilder
{
    /// <summary>
    /// Returns the new/resolved counts relative to <paramref name="previousScan"/>.
    /// Returns an empty delta when there is no previous scan to compare against.
    /// </summary>
    /// <param name="currentScan">The scan the report is being generated for.</param>
    /// <param name="previousScan">The scan immediately preceding it, or null if none.</param>
    /// <param name="allFindings">All suppression-filtered findings across every scan.</param>
    /// <param name="ownersOf">The asset ids that own a discovery (<c>IAssetScope.OwnersOf</c>).</param>
    public FindingDelta Build(
        Scan? currentScan,
        Scan? previousScan,
        IReadOnlyList<DbFinding> allFindings,
        Func<string?, IReadOnlyCollection<string>?> ownersOf)
    {
        if (currentScan is null || previousScan is null)
            return new FindingDelta();

        var newFindings = allFindings
            .Where(f => f.ScanIds.Contains(currentScan.Id) && !f.ScanIds.Contains(previousScan.Id)
                && !ScanCheck.SkippedBy(previousScan, f, ownersOf))
            .ToList();

        var resolvedCount = allFindings.Count(f =>
            f.ScanIds.Contains(previousScan.Id) && !f.ScanIds.Contains(currentScan.Id)
            && !ScanCheck.NotChecked(currentScan, f, ownersOf));

        var newAffectedAssets = newFindings
            .Select(f => f.DiscoveryId)
            .Where(id => !string.IsNullOrEmpty(id))
            .Distinct()
            .Count();

        return new FindingDelta(newFindings.Count, resolvedCount, newAffectedAssets);
    }
}
