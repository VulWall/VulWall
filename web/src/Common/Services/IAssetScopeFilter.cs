using VulWall.Dashboard.Data.Entities.Discovery;
using VulWall.Dashboard.Data.Entities.Finding;

namespace VulWall.Dashboard.Common.Services;

/// <summary>
/// Read-side contract for hiding the data of disabled assets, shared across verticals.
/// Every reader of findings or discoveries applies the returned scope.
/// </summary>
public interface IAssetScopeFilter
{
    /// <summary>
    /// Loads the scope of <paramref name="orgId"/>. The org id is explicit because background
    /// jobs (the executive summary) run without a signed-in user.
    /// </summary>
    Task<AssetScope> GetAsync(string orgId);
}

/// <summary>
/// Which discoveries and findings of one org are visible, by the assets that own them.
/// <para>
/// A discovery is hidden only when <c>asset_ids</c> is non-empty and none of its ids is an
/// existing, enabled asset. A discovery without <c>asset_ids</c> stays visible. A finding is
/// visible when its discovery exists and is visible.
/// </para>
/// Disabling an asset writes nothing to these documents, so re-enabling shows them again.
/// </summary>
public sealed class AssetScope
{
    private readonly HashSet<string> _enabledAssetIds;
    private readonly HashSet<string> _visibleDiscoveryIds = [];
    private readonly HashSet<string> _hiddenDiscoveryIds = [];

    public AssetScope(
        IEnumerable<string> enabledAssetIds,
        IEnumerable<(string Id, IReadOnlyCollection<string>? AssetIds)> discoveries)
    {
        _enabledAssetIds = enabledAssetIds.ToHashSet();
        foreach (var (id, assetIds) in discoveries)
            (IsOwnedByEnabledAsset(assetIds) ? _visibleDiscoveryIds : _hiddenDiscoveryIds).Add(id);
    }

    public bool IsVisible(Discovery discovery) => IsOwnedByEnabledAsset(discovery.AssetIds);

    public bool IsVisible(Finding finding) =>
        finding.DiscoveryId != null && _visibleDiscoveryIds.Contains(finding.DiscoveryId);

    /// <summary>True only for an existing discovery that is hidden (not for an unknown id).</summary>
    public bool IsHidden(string? discoveryId) =>
        discoveryId != null && _hiddenDiscoveryIds.Contains(discoveryId);

    public List<Discovery> Filter(IEnumerable<Discovery> discoveries) => discoveries.Where(IsVisible).ToList();

    public List<Finding> Filter(IEnumerable<Finding> findings) => findings.Where(IsVisible).ToList();

    private bool IsOwnedByEnabledAsset(IReadOnlyCollection<string>? assetIds) =>
        assetIds is not { Count: > 0 } || assetIds.Any(_enabledAssetIds.Contains);
}
