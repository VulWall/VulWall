using VulWall.Dashboard.Common.Services;
using VulWall.Dashboard.Data.Repositories;

namespace VulWall.Dashboard.Assets.Services;

/// <summary>
/// Loads the <see cref="AssetScope"/> of an org. It reads by explicit org id through the
/// public repositories, so it also works in background jobs without a signed-in user.
/// </summary>
public class AssetScopeFilter(
    AssetsPublicRepository assetsRepository,
    DiscoveriesPublicRepository discoveriesRepository) : IAssetScopeFilter
{
    public async Task<AssetScope> GetAsync(string orgId)
    {
        var enabledTask = assetsRepository.GetEnabledIdsAsync(orgId);
        var ownersTask = discoveriesRepository.GetOwnersAsync(orgId);
        await Task.WhenAll(enabledTask, ownersTask);
        return new AssetScope(await enabledTask, await ownersTask);
    }
}
