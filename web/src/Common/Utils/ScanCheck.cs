using VulWall.Dashboard.Data.Entities.Finding;
using VulWall.Dashboard.Data.Entities.Scan;

namespace VulWall.Dashboard.Common.Utils;

/// <summary>
/// Which findings a scan did not check. Scan history (comparisons, report deltas) uses it so
/// that a finding the scanner skipped is not counted as resolved, and is not counted as new
/// when a later scan sees it again. <c>ownersOf</c> gives the asset ids that own a discovery
/// (<see cref="Services.IAssetScope.OwnersOf"/>).
/// </summary>
public static class ScanCheck
{
    /// <summary>
    /// Whether <paramref name="scan"/> did not see <paramref name="finding"/> because it could
    /// not check it: the scanner left it open without proof (<see cref="Scan.UncheckedFindingIds"/>),
    /// or the scan did not target its asset.
    /// </summary>
    public static bool NotChecked(Scan scan, Finding finding, Func<string?, IReadOnlyCollection<string>?> ownersOf) =>
        scan.UncheckedFindingIds.Contains(finding.Id) || OutOfScope(scan, finding, ownersOf);

    /// <summary>
    /// Whether <paramref name="finding"/> already existed when <paramref name="baseline"/> started
    /// and the baseline did not target its asset (it was disabled then). Such a finding is not new
    /// in a later scan. A finding first detected after the baseline started is new, for example
    /// on an asset added after the baseline.
    /// </summary>
    public static bool SkippedBy(Scan baseline, Finding finding, Func<string?, IReadOnlyCollection<string>?> ownersOf) =>
        finding.FirstDetected < (baseline.StartedAt ?? baseline.CreatedAt) && OutOfScope(baseline, finding, ownersOf);

    /// <summary>
    /// The scan targeted no asset at all (every asset disabled; the scanner closes it at once), or
    /// none of the assets that own the finding's discovery. A discovery without owners is in scope
    /// of any scan that targeted something.
    /// </summary>
    private static bool OutOfScope(Scan scan, Finding finding, Func<string?, IReadOnlyCollection<string>?> ownersOf)
    {
        if (scan.TargetedAssets.Count == 0)
            return true;
        // Known limit: these are today's owners (asset_ids now), not the owners at scan time.
        var owners = ownersOf(finding.DiscoveryId);
        return owners is { Count: > 0 } && !owners.Any(id => scan.TargetedAssets.Any(t => t.AssetId == id));
    }
}
