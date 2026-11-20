using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services.ScanTrigger;
using VulWall.Dashboard.Data.Entities.Asset;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Assets.Constants;
using VulWall.Dashboard.Assets.Models;
using VulWall.Dashboard.Assets.Services.DomainVerifier;
using VulWall.Dashboard.Assets.Validation;

namespace VulWall.Dashboard.Assets.Services;

public class AssetsService(
    AssetsRepository assetsRepository,
    ScanTriggerService scanTriggerService,
    IDomainVerifier domainVerifier)
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
            InactiveAssets = stats.InactiveAssets,
            PendingAssets = stats.PendingAssets
        };
    }

    /// <summary>
    /// Returns the domain this user can add + scan in one click — the ownable domain derived
    /// from their verified email — but only when it is not already an existing Domain asset.
    /// Returns null when the email implies no ownable domain (freemail/malformed) or when the
    /// domain is already tracked. The caller must pass the server-trusted verified email; this
    /// method never accepts a client-supplied domain, so it cannot be used to bypass DNS-TXT.
    /// </summary>
    public async Task<string?> GetQuickAddDomainAsync(string? verifiedEmail)
    {
        var domain = EmailDomainMatcher.GetOwnableDomain(verifiedEmail);
        if (domain == null)
        {
            return null;
        }

        var allAssets = await assetsRepository.GetAllAsync();
        var alreadyExists = allAssets.Any(a =>
            a.Type == AssetType.Domain
            && string.Equals(a.Domain, domain, StringComparison.OrdinalIgnoreCase));

        return alreadyExists ? null : domain;
    }

    public async Task<(Asset? Asset, string? Error)> CreateDomainAssetAsync(string domainName, string? userEmail)
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

        // Ownership implied by a matching corporate email domain auto-verifies the asset;
        // everyone else must prove ownership via the DNS-TXT flow before it is enabled.
        var autoVerified = EmailDomainMatcher.IsOwnershipImpliedByEmail(userEmail, domain);

        var asset = new Asset
        {
            // ponytail: reuse DnsVerifiedAt as the "verified" signal so all downstream stats/guards already work; no new VerificationMethod field. Add one only if we need to distinguish email- vs DNS-proof in audit.
            Enabled = autoVerified,
            DnsVerifiedAt = autoVerified ? DateTime.UtcNow : null,
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

    // ponytail: IP ownership verification deferred — temporarily disabled, see <ticket>. Restore add+scan when PTR/A-record gating lands.
    // IP assets auto-enabled with no ownership check — the same abuse vector we closed for domains.
    // Fail closed here so the asset is never created/enabled even if the route is hit directly.
    // The real add+scan logic is preserved below (commented) for the follow-up ticket to restore.
    public Task<(Asset? Asset, string? Error)> CreateIpAssetAsync(string ipAddress)
    {
        return Task.FromResult<(Asset?, string?)>(
            (null, "IP assets are temporarily unavailable while we add ownership verification for them."));

        // var ip = ipAddress.Trim();
        //
        // if (!System.Net.IPAddress.TryParse(ip, out _))
        // {
        //     return (null, "Please enter a valid IP address.");
        // }
        //
        // if (PrivateIpValidator.IsPrivateIp(ip))
        // {
        //     return (null, $"The IP address '{ip}' is a private or reserved address and cannot be added as an asset.");
        // }
        //
        // var asset = new Asset
        // {
        //     Enabled = true,
        //     Type = AssetType.Ip,
        //     Ip = ip,
        //     AddedOn = DateTime.UtcNow
        // };
        //
        // await assetsRepository.CreateAsync(asset);
        // return (asset, null);
    }

    public async Task<VerifyDomainViewModel?> GetVerifyDomainViewModelAsync(string id)
    {
        var asset = await assetsRepository.GetByIdAsync(id);
        if (asset?.Type != AssetType.Domain)
        {
            return null;
        }

        var txtValue = domainVerifier.GenerateVerificationToken(asset.Domain!, asset.OrgId);

        return new VerifyDomainViewModel
        {
            Id = asset.Id,
            Domain = asset.Domain!,
            TxtHost = Consts.TxtRecordName,
            TxtValue = txtValue
        };
    }

    public async Task<(bool Success, string Message)> VerifyDomainAsync(string id)
    {
        var asset = await assetsRepository.GetByIdAsync(id);
        if (asset?.Domain == null)
        {
            return (false, $"Asset with ID {id} not found.");
        }

        var isVerified = await domainVerifier.VerifyDomain(asset.Domain, asset.OrgId);

        if (isVerified)
        {
            asset.DnsVerifiedAt = DateTime.UtcNow;
            asset.Enabled = true;
            await assetsRepository.UpdateAsync(asset);
            return (true, $"Domain {asset.Domain} has been successfully verified.");
        }

        return (false, $"Domain verification failed for {asset.Domain}. Please ensure the TXT record is correctly set.");
    }

    public async Task<(bool Success, string? ErrorMessage)> UpdateAssetStatusAsync(string assetId, bool enabled)
    {
        var asset = await assetsRepository.GetByIdAsync(assetId);
        if (asset == null)
        {
            return (false, $"Asset with ID {assetId} not found.");
        }

        if (asset.Type != AssetType.Ip && asset.DnsVerifiedAt == null)
        {
            return (false, $"Domain {asset.Domain} can not be activated, please first verify the domain.");
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

        var pending = assetsList.Count(a => !a.Enabled && a.Type == AssetType.Domain && a.DnsVerifiedAt == null);

        return new AssetsStatistics
        {
            TotalAssets = assetsList.Count,
            ActiveAssets = assetsList.Count(a => a.Enabled),
            InactiveAssets = assetsList.Count(a => !a.Enabled),
            PendingAssets = pending
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
            AddedOn = asset.AddedOn,
            DnsVerifiedAt = asset.DnsVerifiedAt
        };
    }
}