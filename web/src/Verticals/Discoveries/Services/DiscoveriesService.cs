using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services;
using VulWall.Dashboard.Data.Entities.Discovery;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Discoveries.Models;

namespace VulWall.Dashboard.Discoveries.Services;

public class DiscoveriesService(
    DiscoveriesRepository discoveriesRepository,
    FindingsRepository findingsRepository,
    ScansRepository scansRepository,
    FeatureAccessService featureAccessService)
{
    public async Task<IndexViewModel> GetIndexViewModelAsync()
    {
        var featureAccess = await featureAccessService.GetFeatureAccessAsync();

        // Get latest completed scan to scope child records (IPs, ports)
        var scans = await scansRepository.GetAllAsync();
        var latestDoneScanId = scans
            .Where(s => s.Status == ScanStatus.Done)
            .OrderByDescending(s => s.CreatedAt)
            .FirstOrDefault()?.Id;

        var results = (await discoveriesRepository.FindAsync(e =>
            (e.AssetType == AssetType.Ip && e.ParentId == null)
            || e.AssetType == AssetType.Domain
            || e.AssetType == AssetType.SubDomain
        )).ToList();

        var discoveryIds = results.Select(d => d.Id).ToList();

        var ipDiscoveriesTask = discoveriesRepository.FindAsync(d =>
            d.AssetType == AssetType.Ip && discoveryIds.Contains(d.ParentId)
        );
        var findingsTask = findingsRepository.FindAsync(f =>
            !string.IsNullOrEmpty(f.DiscoveryId) && discoveryIds.Contains(f.DiscoveryId)
        );

        await Task.WhenAll(ipDiscoveriesTask, findingsTask);

        var allIpDiscoveries = (await ipDiscoveriesTask).ToList();
        var findings = (await findingsTask).ToList();

        var ipIds = allIpDiscoveries.Select(ip => ip.Id).Concat(
            results.Where(r => r.AssetType == AssetType.Ip).Select(r => r.Id)
        ).ToList();

        var portDiscoveries = (await discoveriesRepository.FindAsync(d =>
            d.AssetType == AssetType.Port && ipIds.Contains(d.ParentId)
        )).ToList();

        var findingsByDiscovery = findings
            .GroupBy(f => f.DiscoveryId)
            .ToDictionary(g => g.Key!, g => g.ToList());

        var allAssets = results.Select(d => MapDiscoveryToViewModel(d, allIpDiscoveries, portDiscoveries, findingsByDiscovery, latestDoneScanId)).ToList();

        var discoveredIds = allAssets.Select(a => a.Id).ToHashSet();
        var parentAssets = allAssets
            .Where(a => string.IsNullOrEmpty(a.ParentId) || !discoveredIds.Contains(a.ParentId))
            .ToList();
        foreach (var parent in parentAssets)
        {
            parent.Children = allAssets
                .Where(a => a.ParentId == parent.Id && a.Type is AssetType.Domain or AssetType.SubDomain).ToList();
        }

        // Calculate summary stats for teaser (always)
        var domainCount = allAssets.Count(a => a.Type == AssetType.Domain);
        var subdomainCount = allAssets.Count(a => a.Type == AssetType.SubDomain);
        var ipCount = allAssets.Count(a => a.Type == AssetType.Ip);
        var totalPorts = allAssets.Sum(a => a.PortsCount);

        // All users see all assets including subdomain children; state management is Pro-only (locked in UI)
        var visibleAssets = parentAssets;

        return new IndexViewModel
        {
            FeatureAccess = featureAccess,
            Discoveries = visibleAssets,
            // Summary stats (always populated)
            TotalDiscoveries = allAssets.Count,
            DomainCount = domainCount,
            SubdomainCount = subdomainCount,
            IpCount = ipCount,
            PortCount = totalPorts
        };
    }

    public async Task<bool> UpdateOwnershipStatusAsync(string discoveryId, OwnershipStatus ownershipStatus)
    {
        if (string.IsNullOrEmpty(discoveryId))
        {
            return false;
        }

        var discovery = await discoveriesRepository.GetByIdAsync(discoveryId);
        if (discovery == null)
        {
            return false;
        }

        discovery.OwnershipStatus = ownershipStatus;
        await discoveriesRepository.UpdateAsync(discovery);

        return true;
    }

    private DiscoveryItemViewModel MapDiscoveryToViewModel(
        Discovery discovery,
        List<Discovery> ipDiscoveries,
        List<Discovery> portDiscoveries,
        Dictionary<string, List<Data.Entities.Finding.Finding>> findingsByDiscovery,
        string? latestDoneScanId)
    {
        var name = discovery.AssetType switch
        {
            AssetType.Domain => discovery.Domain ?? "Unknown",
            AssetType.SubDomain => discovery.Subdomain ?? "Unknown",
            AssetType.Ip => discovery.Ip ?? "Unknown",
            _ => "Unknown"
        };

        // Filter child records to only show data from the latest completed scan.
        // This prevents stale historical data (old CDN ports, rotated IPs) from accumulating.
        var scopedIpDiscoveries = FilterByScanId(ipDiscoveries, latestDoneScanId);
        var scopedPortDiscoveries = FilterByScanId(portDiscoveries, latestDoneScanId);

        var ipAddress = discovery.AssetType switch
        {
            AssetType.Domain or AssetType.SubDomain => scopedIpDiscoveries
                .Where(ip => ip.ParentId == discovery.Id)
                .OrderByDescending(ip => ip.LastSeen)
                .FirstOrDefault()
                ?.Ip,
            AssetType.Ip => discovery.Ip,
            _ => null
        };

        var ports = GetPortsForAsset(discovery, discovery.AssetType, scopedIpDiscoveries, scopedPortDiscoveries);

        var findings = findingsByDiscovery.GetValueOrDefault(discovery.Id, []);
        var criticalCount = findings.Count(f => f.Severity == Severity.Critical);
        var highCount = findings.Count(f => f.Severity == Severity.High);
        var mediumCount = findings.Count(f => f.Severity == Severity.Medium);
        var lowCount = findings.Count(f => f.Severity == Severity.Low);

        var geoInfo = DiscoveryGeoInfo.FromMetadata(discovery.Metadata);

        return new DiscoveryItemViewModel
        {
            Id = discovery.Id,
            Name = name,
            Type = discovery.AssetType,
            Status = discovery.Status,
            FirstSeen = discovery.FirstSeen,
            LastSeen = discovery.LastSeen,
            IpAddress = discovery.AssetType != AssetType.Ip ? ipAddress : null,
            ParentId = discovery.ParentId,
            Children = [],
            Ports = ports,
            PortsCount = ports.Count,
            ServicesCount = ports.Where(p => p.Service != "unknown").Select(p => p.Service).Distinct().Count(),
            OwnershipStatus = discovery.OwnershipStatus,
            Metadata = discovery.Metadata ?? new Dictionary<string, object?>(),
            CriticalIssues = criticalCount,
            HighIssues = highCount,
            MediumIssues = mediumCount,
            LowIssues = lowCount,
            CountryCode = geoInfo.CountryCode,
            Continent = geoInfo.Continent,
            Isp = geoInfo.Isp,
            CloudProvider = geoInfo.CloudProvider,
            CloudRegion = geoInfo.CloudRegion,
            Waf = geoInfo.Waf
        };
    }

    private List<PortInfo> GetPortsForAsset(
        Discovery discovery,
        AssetType assetType,
        List<Discovery> ipDiscoveries,
        List<Discovery> portDiscoveries)
    {
        IEnumerable<string> parentIds;

        if (assetType == AssetType.Domain || assetType == AssetType.SubDomain)
        {
            parentIds = ipDiscoveries
                .Where(ip => ip.ParentId == discovery.Id)
                .Select(ip => ip.Id);
        }
        else
        {
            parentIds = [discovery.Id];
        }

        var rawPorts = portDiscoveries
            .Where(p => parentIds.Contains(p.ParentId))
            .ToList();

        return rawPorts
            .GroupBy(p => (p.Port ?? 0, p.Protocol ?? "unknown"))
            .Select(g =>
            {
                var representative = g.First();
                return new PortInfo
                {
                    PortNumber = representative.Port ?? 0,
                    Protocol = representative.Protocol ?? "unknown",
                    Service = representative.Service ?? "unknown",
                    State = representative.Status == AssetStatus.Active ? "open" : "closed",
                    IpCount = g.Select(p => p.ParentId).Distinct().Count()
                };
            })
            .ToList();
    }

    /// <summary>
    /// Filters discoveries to only those that participated in the given scan.
    /// If scanId is null, returns all discoveries (graceful fallback when no completed scan exists).
    /// </summary>
    private static List<Discovery> FilterByScanId(List<Discovery> discoveries, string? scanId)
    {
        if (scanId == null)
            return discoveries;

        return discoveries
            .Where(d => d.ScanIds != null && d.ScanIds.Contains(scanId))
            .ToList();
    }

}
