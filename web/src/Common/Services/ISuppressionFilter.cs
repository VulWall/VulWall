using VulWall.Dashboard.Data.Entities.Finding;

namespace VulWall.Dashboard.Common.Services;

/// <summary>
/// Read-side contract for finding suppression, shared across verticals.
/// Write-side operations (Suppress/Unsuppress) remain in the Recommendations vertical.
/// </summary>
public interface ISuppressionFilter
{
    /// <summary>
    /// Returns the active suppressed (discoveryId, findingType) key set for the current
    /// org-scoped context.
    /// </summary>
    Task<HashSet<(string DiscoveryId, string FindingType)>> GetActiveSuppressionKeysAsync();

    /// <summary>
    /// Filters a sequence of findings by excluding open findings whose (discoveryId, findingType)
    /// pair appears in the suppressed key set.
    /// This is the single canonical suppression predicate — all consumers must use this method.
    /// </summary>
    IEnumerable<Finding> FilterSuppressed(IEnumerable<Finding> findings, HashSet<(string DiscoveryId, string FindingType)> suppressedKeys);
}
