using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Common.Services.Mappers;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Data.Entities.Finding;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Recommendations.Models;

namespace VulWall.Dashboard.Recommendations.Services;

public class RecommendationsService(
    FindingsRepository findingsRepository,
    DiscoveriesRepository discoveriesRepository,
    ScansRepository scansRepository,
    KnowledgeBaseCacheService knowledgeBaseCache,
    FindingSuppressionService suppressionService,
    IAssetScopeFilter assetScopeFilter,
    IOrganizationContext organizationContext)
{
    public async Task<RecommendationsIndexViewModel> GetIndexViewModelAsync()
    {
        var allFindingsTask = findingsRepository.GetAllAsync();
        var scansTask = scansRepository.FindAsync(
            predicate: s => s.Status == ScanStatus.Done,
            orderByProperty: s => s.CreatedAt,
            sortDirection: SortDirection.Descending,
            limit: 1);
        var discoveriesTask = discoveriesRepository.GetAllAsync();
        var kbEntriesTask = knowledgeBaseCache.GetAllAsync();
        var suppressedKeysTask = suppressionService.GetActiveSuppressionKeysAsync();
        var activeSuppressionsTask = suppressionService.GetActiveSuppressionsAsync();
        var scopeTask = GetAssetScopeAsync();

        await Task.WhenAll(
            allFindingsTask, scansTask,
            discoveriesTask, kbEntriesTask, suppressedKeysTask, activeSuppressionsTask, scopeTask);

        var scope = await scopeTask;
        var allFindings = scope.Filter(await allFindingsTask);
        var latestScan = (await scansTask).FirstOrDefault();
        var findings = latestScan != null
            ? allFindings.Where(f => f.ScanIds.Contains(latestScan.Id)).ToList()
            : allFindings;

        var openFindings = findings.Where(f => f.Status == "open").ToList();
        var suppressedKeys = await suppressedKeysTask;
        // The Dismissed list leaves out the suppressions of disabled assets' discoveries.
        var activeSuppressions = (await activeSuppressionsTask)
            .Where(s => !scope.IsHidden(s.DiscoveryId))
            .ToList();

        var discoveryDict = scope.Filter(await discoveriesTask).ToDictionary(d => d.Id, d => d);
        var kbByType = (await kbEntriesTask).ToDictionary(kb => kb.FindingType, kb => kb);

        var viewModel = new RecommendationsIndexViewModel();

        viewModel.LastScanAt = latestScan?.CreatedAt;

        // Group findings by FindingType and Severity, skipping groups where all assets are suppressed
        var groupedFindings = openFindings
            .GroupBy(f => new { FindingType = f.FindingType ?? f.Title, f.Severity })
            .Select(g =>
            {
                var first = g.First();
                var kb = first.FindingType != null && kbByType.TryGetValue(first.FindingType, out var entry) ? entry : null;
                var title = kb?.Business?.Title ?? GetMappedTitle(first);
                var findingType = first.FindingType ?? first.Title;

                var affectedAssets = g.Select(f => new AffectedAsset
                {
                    FindingId = f.Id,
                    DiscoveryId = f.DiscoveryId,
                    Target = GetTarget(f.DiscoveryId, discoveryDict),
                    Port = GetPort(f.DiscoveryId, discoveryDict)
                }).ToList();

                // Only keep assets that are NOT actively suppressed for this finding type
                var visibleAssets = affectedAssets
                    .Where(a => a.DiscoveryId == null ||
                                !suppressedKeys.Contains((a.DiscoveryId, findingType)))
                    .ToList();

                // If all affected assets are suppressed, this group has no visible assets
                if (visibleAssets.Count == 0)
                    return null;

                return new GroupedFindingViewModel
                {
                    Title = title,
                    Description = first.Description,
                    Severity = g.Key.Severity,
                    FindingType = first.FindingType,
                    BusinessImpact = BusinessImpactMapper.GetBusinessImpact(first.FindingType),
                    EstimatedEffort = kb?.Metadata?.EstimatedEffort,
                    OwaspCategory = kb?.Metadata?.OwaspCategory,
                    IsExploitable = kb?.Metadata?.IsExploitable,
                    FirstDetected = g.Min(f => f.FirstDetected),
                    LastDetected = g.Max(f => f.LastDetected),
                    HasAIRecommendation = kb != null,
                    IsNew = g.Any(f => f.ScanIds.Count == 1),
                    PrimaryFindingId = first.Id,
                    AffectedAssets = visibleAssets
                };
            })
            .Where(g => g != null)
            .Cast<GroupedFindingViewModel>()
            .ToList();

        foreach (var grouped in groupedFindings)
        {
            switch (grouped.Severity)
            {
                case Severity.Critical:
                    viewModel.CriticalFindings.Add(grouped);
                    break;
                case Severity.High:
                    viewModel.HighFindings.Add(grouped);
                    break;
                case Severity.Medium:
                    viewModel.MediumFindings.Add(grouped);
                    break;
                case Severity.Low:
                    viewModel.LowFindings.Add(grouped);
                    break;
            }
        }

        // Build dismissed/accepted section
        var discoveryTargets = discoveryDict.ToDictionary(
            kvp => kvp.Key,
            kvp => (string?)(kvp.Value.Subdomain ?? kvp.Value.Domain));

        viewModel.DismissedFindings = FindingSuppressionService.BuildDismissedViewModels(
            activeSuppressions, discoveryTargets);

        return viewModel;
    }

    private async Task<AssetScope> GetAssetScopeAsync() =>
        await assetScopeFilter.GetAsync(await organizationContext.GetCurrentOrgIdAsync());

    private static string? GetTarget(string? discoveryId, Dictionary<string, Data.Entities.Discovery.Discovery> discoveryDict)
    {
        if (discoveryId == null || !discoveryDict.TryGetValue(discoveryId, out var discovery))
            return null;
        return discovery.Subdomain ?? discovery.Domain;
    }

    private static int? GetPort(string? discoveryId, Dictionary<string, Data.Entities.Discovery.Discovery> discoveryDict)
    {
        if (discoveryId == null || !discoveryDict.TryGetValue(discoveryId, out var discovery))
            return null;
        return discovery.Port;
    }

    private static string GetMappedTitle(Finding finding)
    {
        if (finding.Source == "testssl")
            return TestSSLTitleMapper.MapTitle(finding.FindingType, finding.Title);

        return finding.Title;
    }

    public async Task<RecommendationDetailViewModel?> GetDetailViewModelAsync(string id)
    {
        var findingTask = findingsRepository.GetByIdAsync(id);
        var kbEntriesTask = knowledgeBaseCache.GetAllAsync();
        var allFindingsTask = findingsRepository.GetAllAsync();
        var scansTask = scansRepository.FindAsync(
            predicate: s => s.Status == ScanStatus.Done,
            orderByProperty: s => s.CreatedAt,
            sortDirection: SortDirection.Descending,
            limit: 1);
        var discoveriesTask = discoveriesRepository.GetAllAsync();
        var suppressedKeysTask = suppressionService.GetActiveSuppressionKeysAsync();
        var scopeTask = GetAssetScopeAsync();

        await Task.WhenAll(
            findingTask, kbEntriesTask,
            allFindingsTask, scansTask, discoveriesTask, suppressedKeysTask, scopeTask);

        var scope = await scopeTask;
        var finding = await findingTask;
        // A finding of a disabled asset (or of no discovery) is not found.
        if (finding == null || !scope.IsVisible(finding))
            return null;

        var suppressedKeys = await suppressedKeysTask;

        var kbByType = (await kbEntriesTask).ToDictionary(kb => kb.FindingType, kb => kb);
        var kb = finding.FindingType != null && kbByType.TryGetValue(finding.FindingType, out var entry) ? entry : null;
        var title = kb?.Business?.Title ?? GetMappedTitle(finding);

        var findingVm = new FindingItemViewModel
        {
            Id = finding.Id,
            Title = title,
            Description = finding.Description,
            Severity = finding.Severity,
            FindingType = finding.FindingType,
            DiscoveryId = finding.DiscoveryId,
            DetectedBy = finding.Source,
            Status = finding.Status,
            Cve = ExtractFirstMetadataValue(finding.Metadata, "cve", "cves"),
            Cwe = ExtractFirstMetadataValue(finding.Metadata, "cwe", "cwes"),
            ScannerRemediation = string.IsNullOrWhiteSpace(finding.Remediation) ? null : finding.Remediation.Trim(),
            References = ReferenceUrls.Extract(finding.References, finding.Metadata),
            BusinessImpact = BusinessImpactMapper.GetBusinessImpact(finding.FindingType),
            VulnerabilityExplanation = kb?.Technical?.VulnerabilityExplanation,
            PotentialImpact = kb?.Technical?.Impact,
            RemediationSteps = kb?.Technical?.RemediationSteps,
            BestPractices = kb?.Technical?.BestPractices,
            EstimatedEffort = kb?.Metadata?.EstimatedEffort,
            Priority = kb?.Business?.Urgency,
            OwaspCategory = kb?.Metadata?.OwaspCategory,
            IsExploitable = kb?.Metadata?.IsExploitable,
            IsNew = finding.ScanIds.Count == 1,
            FirstDetected = finding.FirstDetected,
            LastDetected = finding.LastDetected
        };

        var findingType = finding.FindingType ?? finding.Title;
        var allFindings = scope.Filter(await allFindingsTask);
        var latestScan = (await scansTask).FirstOrDefault();
        var scopedFindings = latestScan != null
            ? allFindings.Where(f => f.ScanIds.Contains(latestScan.Id)).ToList()
            : allFindings;
        var relatedFindings = scopedFindings
            .Where(f => (f.FindingType ?? f.Title) == findingType && f.Status == "open")
            .ToList();

        var discoveryDict = scope.Filter(await discoveriesTask).ToDictionary(d => d.Id, d => d);

        // Load all active suppressions for this finding type so we can show per-asset state.
        // GroupBy + First guards against duplicate rows that could exist before the unique index
        // was added, preventing a ToDictionary crash on the detail page.
        var allSuppressions = await suppressionService.GetActiveSuppressionsAsync();
        var suppressionsByDiscovery = allSuppressions
            .Where(s => s.FindingType == findingType)
            .GroupBy(s => s.DiscoveryId)
            .ToDictionary(g => g.Key, g => g.OrderByDescending(s => s.SuppressedAt).First());

        var affectedAssets = relatedFindings.Select(f =>
        {
            var asset = new AffectedAssetDetail
            {
                FindingId = f.Id,
                DiscoveryId = f.DiscoveryId,
                FirstDetected = f.FirstDetected,
                LastDetected = f.LastDetected
            };

            if (f.DiscoveryId != null && discoveryDict.TryGetValue(f.DiscoveryId, out var disc))
            {
                asset.Target = disc.Subdomain ?? disc.Domain;
                asset.Ip = disc.Ip;
                asset.Port = disc.Port;
                asset.Protocol = disc.Protocol;
                asset.ServiceName = disc.Service;
            }

            if (f.DiscoveryId != null && suppressionsByDiscovery.TryGetValue(f.DiscoveryId, out var sup))
            {
                asset.IsSuppressed = true;
                asset.SuppressionId = sup.Id;
                asset.SuppressionStatus = sup.Status;
            }

            return asset;
        })
        .OrderByDescending(a => a.LastDetected)
        .ToList();

        return new RecommendationDetailViewModel
        {
            Finding = findingVm,
            AffectedAssets = affectedAssets,
            ShowAiKeyHint = string.IsNullOrWhiteSpace(ServiceSettings.Instance.AnthropicApiKey)
        };
    }



    /// <summary>
    /// Reads the first string value from one or more BsonDocument metadata keys.
    /// Supports both BsonString ("cwe") and BsonArray ("cwes", "cves") forms.
    /// Returns null if the document is null, the key is absent, or the value is empty.
    /// </summary>
    private static string? ExtractFirstMetadataValue(MongoDB.Bson.BsonDocument? metadata, params string[] keys)
    {
        if (metadata == null) return null;
        foreach (var key in keys)
        {
            if (!metadata.Contains(key)) continue;
            var val = metadata[key];
            if (val.IsBsonArray)
            {
                var s = val.AsBsonArray.FirstOrDefault(e => e.IsString)?.AsString;
                if (!string.IsNullOrWhiteSpace(s)) return s;
            }
            else if (val.IsString)
            {
                var s = val.AsString;
                if (!string.IsNullOrWhiteSpace(s)) return s;
            }
        }
        return null;
    }
}
