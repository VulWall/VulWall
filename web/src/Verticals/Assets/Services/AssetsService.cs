using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services.ScanTrigger;
using VulWall.Dashboard.Data.Entities.Asset;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Assets.Models;
using VulWall.Dashboard.Assets.Validation;

namespace VulWall.Dashboard.Assets.Services;

public class AssetsService(
    AssetsRepository assetsRepository,
    ScanTriggerService scanTriggerService)
{
    public async Task<IndexViewModel> GetAssetsAsync()
    {
        var allAssets = await assetsRepository.GetAllAsync();
        var assets = allAssets.Select(MapAssetToViewModel).ToList();
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
        return (asset, null);
    }

    public async Task<(bool Success, string? ErrorMessage)> UpdateAssetStatusAsync(string assetId, bool enabled)
    {
        var asset = await assetsRepository.GetByIdAsync(assetId);
        if (asset == null)
        {
            return (false, $"Asset with ID {assetId} not found.");
        }

        asset.Enabled = enabled;
        await assetsRepository.UpdateAsync(asset);

        return (true, null);
    }

    public async Task<(bool Success, string? Error)> DeleteAssetAsync(string id)
    {
        var asset = await assetsRepository.GetByIdAsync(id);
        if (asset == null)
            return (false, null);

        if (await IsScanInProgressAsync())
            return (false, "A scan is currently running. Please wait for it to complete before removing assets.");

        await assetsRepository.DeleteAsync(id);
        return (true, null);
    }

    public Task<bool> IsScanInProgressAsync() => scanTriggerService.IsScanInProgressAsync();

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

    private static AssetItemViewModel MapAssetToViewModel(Asset asset)
    {
        return new AssetItemViewModel
        {
            Id = asset.Id,
            Name = asset.Type == AssetType.Domain ? asset.Domain! : asset.Ip!,
            Type = asset.Type,
            Enabled = asset.Enabled,
            AddedOn = asset.AddedOn
        };
    }
}