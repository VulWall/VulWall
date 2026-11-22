using VulWall.Dashboard.Common.Services;
using VulWall.Dashboard.Data.Entities.Discovery;
using VulWall.Dashboard.Data.Entities.Finding;
using VulWall.Dashboard.Data.Repositories;

namespace VulWall.Dashboard.Assets.Services;

/// <summary>
/// Loads the <see cref="IAssetScope"/> of an org. It reads by explicit org id through the
/// public repositories, so it also works in background jobs without a signed-in user.
/// </summary>
public class AssetScopeFilter(
    AssetsPublicRepository assetsRepository,
    DiscoveriesPublicRepository discoveriesRepository) : IAssetScopeFilter
{
    public async Task<IAssetScope> GetAsync(string orgId, IReadOnlyCollection<string>? discoveryIds = null)
    {
        var enabledTask = assetsRepository.GetEnabledIdsAsync(orgId);
        var ownersTask = discoveriesRepository.GetOwnersAsync(orgId, discoveryIds);
        await Task.WhenAll(enabledTask, ownersTask);
        return new AssetScope(await enabledTask, await ownersTask);
    }
}

/// <summary>
/// The visibility rule: a discovery is visible when it has no <c>asset_ids</c> field (written
/// before ownership was recorded) or one of its ids is an existing, enabled asset. An empty
/// <c>asset_ids</c> is hidden: only an asset delete empties it, and the discovery is about to go.
/// </summary>
internal sealed class AssetScope : IAssetScope
{
    private readonly HashSet<string> _enabledAssetIds;
    private readonly Dictionary<string, IReadOnlyCollection<string>?> _owners = [];
    private readonly HashSet<string> _visibleDiscoveryIds = [];
    private readonly HashSet<string> _hiddenDiscoveryIds = [];

    public AssetScope(
        IEnumerable<string> enabledAssetIds,
        IEnumerable<(string Id, IReadOnlyCollection<string>? AssetIds)> discoveries)
    {
        _enabledAssetIds = enabledAssetIds.ToHashSet();
        foreach (var (id, assetIds) in discoveries)
        {
            _owners[id] = assetIds;
            (IsOwnedByEnabledAsset(assetIds) ? _visibleDiscoveryIds : _hiddenDiscoveryIds).Add(id);
        }
    }

    public bool IsVisible(Discovery discovery) => IsOwnedByEnabledAsset(discovery.AssetIds);

    public bool IsVisible(Finding finding) =>
        finding.DiscoveryId != null && _visibleDiscoveryIds.Contains(finding.DiscoveryId);

    public bool IsHidden(string? discoveryId) =>
        discoveryId != null && _hiddenDiscoveryIds.Contains(discoveryId);

    public bool IsVisibleDiscovery(string? discoveryId) =>
        discoveryId != null && _visibleDiscoveryIds.Contains(discoveryId);

    public IReadOnlyCollection<string>? OwnersOf(string? discoveryId) =>
        discoveryId != null ? _owners.GetValueOrDefault(discoveryId) : null;

    public List<Discovery> Filter(IEnumerable<Discovery> discoveries) => discoveries.Where(IsVisible).ToList();

    public List<Finding> Filter(IEnumerable<Finding> findings) => findings.Where(IsVisible).ToList();

    private bool IsOwnedByEnabledAsset(IReadOnlyCollection<string>? assetIds) =>
        assetIds is null || assetIds.Any(_enabledAssetIds.Contains);
}
