using MongoDB.Driver;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services.ScanTrigger;
using VulWall.Dashboard.Data.Entities.Asset;
using VulWall.Dashboard.Data.Entities.Discovery;
using VulWall.Dashboard.Data.Entities.Finding;
using VulWall.Dashboard.Data.Entities.FindingSuppression;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Assets.Models;
using VulWall.Dashboard.Assets.Validation;
using ScanCoverageRecord = VulWall.Dashboard.Data.Entities.ScanCoverage.ScanCoverage;
using SortDirection = VulWall.Dashboard.Common.Contracts.Enums.SortDirection;

namespace VulWall.Dashboard.Assets.Services;

public class AssetsService(
    AssetsRepository assetsRepository,
    ScansRepository scansRepository,
    ScanTriggerService scanTriggerService,
    DiscoveriesRepository discoveriesRepository,
    FindingsRepository findingsRepository,
    FindingSuppressionsRepository suppressionsRepository,
    ScanCoverageRepository scanCoverageRepository)
{
    public async Task<IndexViewModel> GetAssetsAsync()
    {
        var allAssets = await assetsRepository.GetAllAsync();
        var latestDone = (await scansRepository.FindAsync(
            predicate: s => s.Status == ScanStatus.Done,
            orderByProperty: s => s.CreatedAt,
            sortDirection: SortDirection.Descending,
            limit: 1)).FirstOrDefault();
        var assets = allAssets.Select(a => MapAssetToViewModel(a, latestDone)).ToList();
        var stats = await GetStatisticsAsync();

        return new IndexViewModel
        {
            Assets = assets,
            TotalAssets = stats.TotalAssets,
            ActiveAssets = stats.ActiveAssets,
            InactiveAssets = stats.InactiveAssets
        };
    }

    /// <summary>
    /// Self-hosted installs have no ownership check: the asset is enabled immediately. The add
    /// page warns the user to only scan assets they own or are authorized to test.
    /// </summary>
    public async Task<(Asset? Asset, string? Error)> CreateDomainAssetAsync(string domainName)
    {
        var domain = SanitizeDomain(domainName);

        if (System.Net.IPAddress.TryParse(domain, out _))
        {
            return (null, "Please enter a domain name, not an IP address. Use the IP asset type for IP addresses.");
        }

        if (await PrivateIpValidator.DomainResolvesToPrivateIpAsync(domain))
        {
            return (null, $"The domain '{domain}' resolves to a private or reserved IP address and cannot be added as an asset.");
        }

        var asset = new Asset
        {
            Enabled = true,
            Type = AssetType.Domain,
            Domain = domain,
            AddedOn = DateTime.UtcNow
        };

        await assetsRepository.CreateAsync(asset);
        await RecordOwnershipAsync(asset);
        return (asset, null);
    }

    private static string SanitizeDomain(string input)
    {
        var domain = input.Trim().ToLowerInvariant();

        // Remove protocol prefixes
        domain = domain
            .Replace("https://", "")
            .Replace("http://", "");

        // Remove trailing slash and any path
        var slashIndex = domain.IndexOf('/');
        if (slashIndex > 0)
        {
            domain = domain[..slashIndex];
        }

        // Remove query string if present
        var queryIndex = domain.IndexOf('?');
        if (queryIndex > 0)
        {
            domain = domain[..queryIndex];
        }

        // Remove port if present (e.g., example.com:8080)
        var colonIndex = domain.IndexOf(':');
        if (colonIndex > 0)
        {
            domain = domain[..colonIndex];
        }

        return domain.Trim();
    }

    public async Task<(Asset? Asset, string? Error)> CreateIpAssetAsync(string ipAddress)
    {
        var ip = ipAddress.Trim();

        if (!System.Net.IPAddress.TryParse(ip, out _))
        {
            return (null, "Please enter a valid IP address.");
        }

        if (PrivateIpValidator.IsPrivateIp(ip))
        {
            return (null, $"The IP address '{ip}' is a private or reserved address and cannot be added as an asset.");
        }

        var asset = new Asset
        {
            Enabled = true,
            Type = AssetType.Ip,
            Ip = ip,
            AddedOn = DateTime.UtcNow
        };

        await assetsRepository.CreateAsync(asset);
        await RecordOwnershipAsync(asset);
        return (asset, null);
    }

    public const string ScanInProgressToggleError =
        "A scan is running. Wait for it to finish before you enable or disable assets.";

    public const string ScanInProgressDeleteError =
        "A scan is running. Wait for it to finish before you delete assets.";

    public const string DeletingToggleError =
        "This asset's delete did not finish. Delete it again to finish.";

    public const string DeleteNotFinishedError =
        "The delete did not finish. Delete the asset again to finish.";

    // Enable, disable and delete are refused while a scan is queued or running: the scanner reads
    // the enabled assets once, when the scan starts, and would keep scanning (and writing results
    // for) an asset that was disabled or deleted after that.
    //
    // Enable and disable: the in-progress check runs right before the write, so the window between
    // the two is one database round-trip. A queued scan already counts as in progress, so only a
    // scheduled scan that the scanner inserts in that window can slip through. The cost is results
    // for one asset from one scan; the next scan leaves the asset out.
    //
    // Delete: a scan that slipped through would add the asset back to asset_ids after the cascade
    // removed it, and that data would stay hidden for good. So delete disables the asset first and
    // checks again: a scan that starts after the disable does not read the asset, and one that
    // started before it is seen by the second check, which stops the delete and sets enabled back
    // to what it was. That scan already read the asset, so the restore changes nothing it scans,
    // and the Assets page stays truthful. What is left is the scanner's own gap between reading
    // the assets and inserting the scan, which is in memory. Closing it fully would need a lock
    // shared with the scanner, which is not worth it for this.
    //
    // After the second check the delete sets deleting (with enabled false) before it touches a
    // discovery, and nothing clears it: a delete that fails part-way leaves an asset that can
    // only be deleted again. Enable and disable are refused for it, the scanner neither scans it
    // nor records it on discoveries, and the web app treats it as disabled. So an empty
    // asset_ids can only belong to a deleting asset (or to assets that no longer exist), and
    // every delete may sweep all of the org's empty discoveries: they are all on their way out.
    // Were a half-deleted asset enabled again, another asset's delete would remove its data.

    public async Task<(bool Success, string? ErrorMessage)> UpdateAssetStatusAsync(string assetId, bool enabled)
    {
        var asset = await assetsRepository.GetByIdAsync(assetId);
        if (asset == null)
            return (false, NotFoundError(assetId));
        if (asset.Deleting)
            return (false, DeletingToggleError);

        if (await IsScanInProgressAsync())
            return (false, ScanInProgressToggleError);

        // Partial and conditional: a full replace would race the delete, which sets deleting in
        // between and would get it overwritten.
        var a = Builders<Asset>.Filter;
        var matched = await assetsRepository.UpdateOneAsync(
            a.Eq(x => x.Id, assetId) & a.Ne(x => x.Deleting, true),
            Builders<Asset>.Update.Set(x => x.Enabled, enabled));
        if (matched == 0)
            return (false, await assetsRepository.GetByIdAsync(assetId) == null ? NotFoundError(assetId) : DeletingToggleError);

        return (true, null);
    }

    private static string NotFoundError(string assetId) => $"Asset with ID {assetId} not found.";

    public async Task<(bool Success, string? Error)> DeleteAssetAsync(string id)
    {
        var asset = await assetsRepository.GetByIdAsync(id);
        if (asset == null)
            return (false, null);

        if (await IsScanInProgressAsync())
            return (false, ScanInProgressDeleteError);

        // Disable first, then check again, then mark (see the comment above UpdateAssetStatusAsync).
        var byId = Builders<Asset>.Filter.Eq(a => a.Id, asset.Id);
        await assetsRepository.UpdateOneAsync(byId, Builders<Asset>.Update.Set(a => a.Enabled, false));
        if (await IsScanInProgressAsync())
        {
            await assetsRepository.UpdateOneAsync(byId, Builders<Asset>.Update.Set(a => a.Enabled, asset.Enabled));
            return (false, ScanInProgressDeleteError);
        }
        await assetsRepository.UpdateOneAsync(byId,
            Builders<Asset>.Update.Set(a => a.Enabled, false).Set(a => a.Deleting, true));

        await DeleteOwnedDataAsync(asset.Id);

        // Last, so a run that fails part-way can be retried from the Assets page. Only a marked
        // asset: the mark is what kept its data safe from the steps above.
        if (await assetsRepository.DeleteManyAsync(byId & Builders<Asset>.Filter.Eq(a => a.Deleting, true)) == 0)
            return (false, DeleteNotFinishedError);
        return (true, null);
    }

    /// <summary>Discovery ids per <c>$in</c> in the cascade. Tests set it low to cross batches.</summary>
    internal int DeleteBatchSize { get; init; } = 1000;

    /// <summary>
    /// Removes the asset from <c>asset_ids</c> and deletes the discoveries no asset owns any more,
    /// with their findings, suppressions and scan coverage. Scans and the knowledge base stay.
    /// Every write is org-scoped by the repositories.
    ///
    /// Only a discovery whose <c>asset_ids</c> is now empty is deleted, never "every discovery
    /// that holds this id": whoever controls DNS under one asset can make the scanner add that
    /// asset to another asset's IP. A discovery without <c>asset_ids</c> is never deleted.
    ///
    /// The same pull also removes the ids of assets that no longer exist: a scan message still in
    /// flight when an earlier delete ran can have written one after it (the scanner's asset guard
    /// narrows that window but cannot close it). A discovery left empty by that is no one's and
    /// goes too. Still "empty after the pull", never "holds a given id".
    ///
    /// MongoDB runs without transactions here, so a retry must finish a run that stopped at any
    /// step. The scanner never writes an empty <c>asset_ids</c> (it omits the field or adds with
    /// $addToSet), so an empty one can only come from a delete's pull: the org's empty
    /// discoveries are exactly the ones still to delete, also when an earlier run stopped after
    /// the pull. They stay as the marker until the last step deletes them. Their asset is marked
    /// deleting and can never be enabled again (see above), so sweeping them in any asset's
    /// delete is safe.
    /// </summary>
    private async Task DeleteOwnedDataAsync(string assetId)
    {
        var d = Builders<Discovery>.Filter;

        // Recorded ids first, existing assets second: an asset added in between was inserted
        // before any discovery could hold its id, so it is either not recorded yet or exists.
        var recorded = await discoveriesRepository.GetRecordedAssetIdsAsync();
        var existing = (await assetsRepository.GetAllAsync()).Select(a => a.Id).ToHashSet();
        var removed = recorded.Where(id => !existing.Contains(id)).Append(assetId).Distinct().ToList();
        await discoveriesRepository.UpdateManyAsync(
            d.AnyIn(x => x.AssetIds, removed),
            Builders<Discovery>.Update.PullAll(x => x.AssetIds, removed));

        var ownerless = d.Size(x => x.AssetIds, 0);
        var orphanIds = await discoveriesRepository.FindIdsAsync(ownerless);

        foreach (var selected in orphanIds.Chunk(DeleteBatchSize))
        {
            // Still empty: a discovery that got an owner since the select keeps its findings and,
            // above all, the suppressions the user made.
            var batch = await discoveriesRepository.FindIdsAsync(d.In(x => x.Id, selected) & ownerless);
            if (batch.Count == 0)
                continue;

            await findingsRepository.DeleteManyAsync(Builders<Finding>.Filter.In(x => x.DiscoveryId, batch));
            await suppressionsRepository.DeleteManyAsync(Builders<FindingSuppression>.Filter.In(x => x.DiscoveryId, batch));
            await scanCoverageRepository.DeleteManyAsync(
                Builders<ScanCoverageRecord>.Filter.In(x => x.DiscoveryId, batch));

            // Before the discoveries go: the empty ones are the only record of what is deleted.
            // An IP left pointing at a deleted parent is dropped from the Discoveries page;
            // without a parent it is shown on its own, and the next scan re-parents it. A
            // discovery without asset_ids is not touched.
            await discoveriesRepository.UpdateManyAsync(
                d.In(x => x.ParentId, batch) & d.SizeGt(x => x.AssetIds, 0),
                Builders<Discovery>.Update.Unset(x => x.ParentId));

            // Empty again in the filter: a discovery that got an owner since the select stays.
            await discoveriesRepository.DeleteManyAsync(d.In(x => x.Id, batch) & ownerless);
        }
    }

    /// <summary>
    /// Records a new asset on the discoveries that earlier scans already found for it, as its own
    /// first scan would (scanner domain and port ingestion): a domain asset's own host, the
    /// addresses that host resolves to now, and their ports; an IP asset's IP and its ports. So
    /// <c>api.a.com</c> added after <c>a.com</c> found it owns that data at once, and disabling
    /// or deleting <c>a.com</c> no longer hides or deletes it. Uses the recorded resolution, not
    /// a new DNS lookup. Only adds ($addToSet) to existing, org-scoped discoveries.
    ///
    /// Runs after the asset insert: a delete that runs meanwhile pulls only ids of assets that do
    /// not exist (see DeleteOwnedDataAsync), so it cannot pull this one.
    /// </summary>
    private async Task RecordOwnershipAsync(Asset asset)
    {
        var d = Builders<Discovery>.Filter;
        var add = Builders<Discovery>.Update.AddToSet(x => x.AssetIds, asset.Id);

        List<string> ips;
        if (asset.Type == AssetType.Domain)
        {
            var hostId = DiscoveryIds.ForDomainAsset(asset.OrgId, asset.Domain!);
            await discoveriesRepository.UpdateManyAsync(d.Eq(x => x.Id, hostId), add);
            ips = await discoveriesRepository.GetCurrentIpsAsync(hostId);
        }
        else
        {
            ips = [asset.Ip!];
        }

        // The IP before its ports, as the scanner does (shared.AddIPAssetID).
        foreach (var ip in ips)
        {
            await discoveriesRepository.UpdateManyAsync(d.Eq(x => x.Id, DiscoveryIds.Ip(asset.OrgId, ip)), add);
            await discoveriesRepository.UpdateManyAsync(d.Eq(x => x.AssetType, AssetType.Port) & d.Eq(x => x.Ip, ip), add);
        }
    }

    public Task<bool> IsScanInProgressAsync() => scanTriggerService.IsScanInProgressAsync();

    /// <summary>
    /// Decides what to offer after an asset is added. "Never had a scan" means no scan document
    /// of any status exists for the organization.
    /// </summary>
    public async Task<AssetAddedScanState> GetAssetAddedScanStateAsync()
    {
        if (await IsScanInProgressAsync())
            return AssetAddedScanState.ScanInProgress;

        return await scansRepository.ExistsAsync(_ => true)
            ? AssetAddedScanState.Idle
            : AssetAddedScanState.FirstScan;
    }

    public async Task<AssetsStatistics> GetStatisticsAsync()
    {
        var allAssets = await assetsRepository.GetAllAsync();
        var assetsList = allAssets.ToList();

        return new AssetsStatistics
        {
            TotalAssets = assetsList.Count,
            ActiveAssets = assetsList.Count(a => a.Enabled),
            InactiveAssets = assetsList.Count(a => !a.Enabled)
        };
    }

    private static AssetItemViewModel MapAssetToViewModel(Asset asset, Scan? latestDone)
    {
        return new AssetItemViewModel
        {
            Id = asset.Id,
            Name = asset.Type == AssetType.Domain ? asset.Domain! : asset.Ip!,
            Type = asset.Type,
            Enabled = asset.Enabled,
            Deleting = asset.Deleting,
            AddedOn = asset.AddedOn,
            ScanNotice = ScanNotice(asset.Id, latestDone)
        };
    }

    /// <summary>
    /// A calm note for an asset that the latest completed scan could not fully check. Its open
    /// issues were kept, not resolved.
    /// </summary>
    internal static string? ScanNotice(string assetId, Scan? latestDone)
    {
        var reasons = latestDone?.DegradedAssets
            .Where(d => d.AssetId == assetId)
            .Select(d => d.Reason)
            .ToList();
        if (reasons is null || reasons.Count == 0)
            return null;
        return reasons.Contains(DegradedAsset.RootNxDomain)
            ? "Domain does not resolve. Issues on it and its subdomains close once 3 scans in a row confirm it is gone."
            : "The last scan couldn't check everything for this domain, so its open issues were kept.";
    }
}