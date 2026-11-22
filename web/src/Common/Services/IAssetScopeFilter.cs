using VulWall.Dashboard.Data.Entities.Discovery;
using VulWall.Dashboard.Data.Entities.Finding;

namespace VulWall.Dashboard.Common.Services;

/// <summary>
/// Read-side contract for hiding the data of disabled assets, shared across verticals.
/// Every reader of findings or discoveries applies the returned scope.
/// The Assets vertical implements it.
/// </summary>
public interface IAssetScopeFilter
{
    /// <summary>
    /// Loads the scope of <paramref name="orgId"/>. The org id is explicit because background
    /// jobs (the executive summary) run without a signed-in user. With
    /// <paramref name="discoveryIds"/>, only those discoveries are loaded: the scope then knows
    /// nothing about other ids, so pass every discovery id the caller will ask about.
    /// </summary>
    Task<IAssetScope> GetAsync(string orgId, IReadOnlyCollection<string>? discoveryIds = null);
}

/// <summary>
/// Which discoveries and findings of one org are visible, by the assets that own them
/// (<c>discoveries.asset_ids</c>). Disabling an asset writes nothing to these documents,
/// so re-enabling shows them again.
/// </summary>
public interface IAssetScope
{
    bool IsVisible(Discovery discovery);

    /// <summary>A finding is visible when its discovery exists and is visible.</summary>
    bool IsVisible(Finding finding);

    /// <summary>True only for a known discovery that is hidden (not for an unknown id).</summary>
    bool IsHidden(string? discoveryId);

    /// <summary>The <c>asset_ids</c> of a known discovery; null when unknown or not recorded.</summary>
    IReadOnlyCollection<string>? OwnersOf(string? discoveryId);

    List<Discovery> Filter(IEnumerable<Discovery> discoveries);

    List<Finding> Filter(IEnumerable<Finding> findings);
}
