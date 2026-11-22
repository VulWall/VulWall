using VulWall.Dashboard.Data.Entities.Finding;
using VulWall.Dashboard.Data.Entities.Scan;

namespace VulWall.Dashboard.Common.Utils;

/// <summary>
/// Which findings a scan did not check: the scanner left them open without proof
/// (<see cref="Scan.UncheckedFindingIds"/>), or the scan did not target their asset (disabled
/// then). Scan history (comparisons, report deltas) uses it so that such a finding is not
/// counted as resolved, and is not counted as new when a later scan sees it again.
/// <c>ownersOf</c> gives the asset ids that own a discovery (<see cref="Services.IAssetScope.OwnersOf"/>).
/// </summary>
public static class ScanCheck
{
    /// <summary>Whether <paramref name="scan"/> did not check <paramref name="finding"/>.</summary>
    public static bool NotChecked(Scan scan, Finding finding, Func<string?, IReadOnlyCollection<string>?> ownersOf) =>
        scan.UncheckedFindingIdSet.Contains(finding.Id) || OutOfScope(scan, finding, ownersOf);

    /// <summary>
    /// Whether <paramref name="finding"/> already existed when <paramref name="baseline"/> ran and
    /// the baseline did not check it. Such a finding is not new in a later scan. An unchecked
    /// finding always existed before the baseline (the scanner lists only open findings the scan
    /// did not see). A finding of an asset the baseline did not target is new when it was first
    /// detected after the baseline started, for example on an asset added after the baseline.
    /// </summary>
    public static bool SkippedBy(Scan baseline, Finding finding, Func<string?, IReadOnlyCollection<string>?> ownersOf) =>
        baseline.UncheckedFindingIdSet.Contains(finding.Id)
        || (finding.FirstDetected < (baseline.StartedAt ?? baseline.CreatedAt) && OutOfScope(baseline, finding, ownersOf));

    /// <summary>
    /// The scan targeted no asset at all (every asset disabled; the scanner closes it at once), or
    /// none of the assets that own the finding's discovery (a disabled asset, or an empty
    /// <c>asset_ids</c> while a delete is pending). A discovery without <c>asset_ids</c>, or one
    /// that is unknown, is in scope of any scan that targeted something.
    /// </summary>
    private static bool OutOfScope(Scan scan, Finding finding, Func<string?, IReadOnlyCollection<string>?> ownersOf)
    {
        if (scan.TargetedAssets.Count == 0)
            return true;
        // Known limit: these are today's owners (asset_ids now), not the owners at scan time.
        var owners = ownersOf(finding.DiscoveryId);
        return owners != null && !owners.Any(id => scan.TargetedAssets.Any(t => t.AssetId == id));
    }
}
