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
    /// org-scoped context (authenticated paths).
    /// </summary>
    Task<HashSet<(string DiscoveryId, string FindingType)>> GetActiveSuppressionKeysAsync();

    /// <summary>
    /// Returns the active suppressed (discoveryId, findingType) key set for the given org,
    /// using the public (non-org-scoped) repository. Used by unauthenticated paths such as
    /// shared reports and public certificates.
    /// </summary>
    Task<HashSet<(string DiscoveryId, string FindingType)>> GetActiveSuppressionKeysForOrgAsync(string orgId);

    /// <summary>
    /// Filters a sequence of findings by excluding open findings whose (discoveryId, findingType)
    /// pair appears in the suppressed key set.
    /// This is the single canonical suppression predicate — all consumers must use this method.
    /// </summary>
    IEnumerable<Finding> FilterSuppressed(IEnumerable<Finding> findings, HashSet<(string DiscoveryId, string FindingType)> suppressedKeys);
}
