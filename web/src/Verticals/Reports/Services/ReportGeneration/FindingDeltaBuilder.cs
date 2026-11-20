using VulWall.Dashboard.Reports.Models;
using DbFinding = VulWall.Dashboard.Data.Entities.Finding.Finding;

namespace VulWall.Dashboard.Reports.Services.ReportGeneration;

/// <summary>
/// Computes how the finding set changed between the current scan and the previous one.
/// A finding entity accumulates the IDs of every scan it appeared in, so membership of a
/// scan is determined by whether that scan's ID is present in the finding's <c>ScanIds</c>.
/// </summary>
public class FindingDeltaBuilder
{
    /// <summary>
    /// Returns the new/resolved counts relative to <paramref name="previousScanId"/>.
    /// Returns an empty delta when there is no previous scan to compare against.
    /// </summary>
    /// <param name="currentScanId">The scan the report is being generated for.</param>
    /// <param name="previousScanId">The scan immediately preceding it, or null if none.</param>
    /// <param name="allFindings">All suppression-filtered findings across every scan.</param>
    public FindingDelta Build(
        string? currentScanId,
        string? previousScanId,
        IReadOnlyList<DbFinding> allFindings)
    {
        if (string.IsNullOrEmpty(currentScanId) || string.IsNullOrEmpty(previousScanId))
            return new FindingDelta();

        var newFindings = allFindings
            .Where(f => f.ScanIds.Contains(currentScanId) && !f.ScanIds.Contains(previousScanId))
            .ToList();

        var resolvedCount = allFindings.Count(f =>
            f.ScanIds.Contains(previousScanId) && !f.ScanIds.Contains(currentScanId));

        var newAffectedAssets = newFindings
            .Select(f => f.DiscoveryId)
            .Where(id => !string.IsNullOrEmpty(id))
            .Distinct()
            .Count();

        return new FindingDelta(newFindings.Count, resolvedCount, newAffectedAssets);
    }
}
