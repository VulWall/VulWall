using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Models;
using VulWall.Dashboard.Common.Services;
using VulWall.Dashboard.Common.Services.Mappers;
using VulWall.Dashboard.Common.Utils;
using static VulWall.Dashboard.Common.Utils.SecurityScoreCalculator;

namespace VulWall.Dashboard.Dashboard.Services;

public class SecurityScoreService(
    KnowledgeBaseCacheService knowledgeBaseCache) : ISecurityScoreProvider
{
    public async Task<SecurityScoreResult> CalculateSecurityScoreAsync(
        List<Data.Entities.Finding.Finding> allFindings,
        List<Data.Entities.Discovery.Discovery> allDiscoveries,
        List<Data.Entities.Scan.Scan> recentDoneScans)
    {
        var openFindings = allFindings.Where(f => f.Status == "open").ToList();

        if (openFindings.Count == 0)
        {
            var perfect = SecurityScoreCalculation.Perfect;
            return MapToResult(perfect, trend: 0);
        }

        var discoveryAssetTypes = allDiscoveries.ToDictionary(d => d.Id, d => d.AssetType);

        var kbEntries = (await knowledgeBaseCache.GetAllAsync()).ToList();
        var kbByType = kbEntries.ToDictionary(kb => kb.FindingType, kb => kb);

        var groups = BuildFindingGroupsWithEnrichment(openFindings, discoveryAssetTypes, kbByType);
        var calculation = SecurityScoreCalculator.Calculate(groups, DateTime.UtcNow);
        var trend = CalculateTrend(allFindings, recentDoneScans, discoveryAssetTypes);

        return MapToResult(calculation, trend);
    }

    private static List<FindingGroupInput> BuildFindingGroupsWithEnrichment(
        List<Data.Entities.Finding.Finding> findings,
        Dictionary<string, AssetType> discoveryAssetTypes,
        Dictionary<string, Data.Entities.KnowledgeBase.KnowledgeBaseEntry> kbByType)
    {
        var groups = SecurityScoreCalculator.BuildFindingGroups(findings, discoveryAssetTypes);

        // Build a lookup keyed on the same composite used by BuildFindingGroups' GroupBy
        // (FindingType ?? Title, Severity, Source) to reliably match groups to their first finding
        var firstFindingByGroup = findings
            .GroupBy(f => new { FindingType = f.FindingType ?? f.Title, f.Severity, Source = f.Source ?? "" })
            .ToDictionary(
                g => (g.Key.FindingType, g.Key.Severity, g.Key.Source),
                g => g.First());

        foreach (var group in groups)
        {
            // Match using the first finding's raw title (which BuildFindingGroups sets as Title),
            // then look up via FindingType to correctly handle findings where FindingType != Title
            var matchingEntry = firstFindingByGroup
                .FirstOrDefault(kvp =>
                    kvp.Key.Severity == group.Severity &&
                    kvp.Key.Source == group.Source &&
                    kvp.Value.Title == group.Title);

            if (matchingEntry.Value is not { } first)
                continue;

            // Enrich title from KB, then TestSSL mapper, then fall back to original title
            var kb = first.FindingType != null && kbByType.TryGetValue(first.FindingType, out var entry)
                ? entry
                : null;

            group.Title = kb?.Business?.Title
                          ?? (first.Source == "testssl"
                              ? TestSSLTitleMapper.MapTitle(first.FindingType, first.Title)
                              : first.Title);

            group.DetailsUrl = $"/Recommendations/Detail/{first.Id}";
        }

        return groups;
    }

    /// <summary>
    /// Calculates trend using pre-fetched data — no DB calls.
    /// </summary>
    private static int CalculateTrend(
        List<Data.Entities.Finding.Finding> allFindings,
        List<Data.Entities.Scan.Scan> recentDoneScans,
        Dictionary<string, AssetType> discoveryAssetTypes)
    {
        if (recentDoneScans.Count < 2)
            return 0;

        var scansList = recentDoneScans
            .OrderByDescending(s => s.CreatedAt)
            .Take(5)
            .ToList();

        var historicalScores = new List<int>();
        foreach (var scan in scansList.Skip(1))
        {
            var scanFindings = allFindings
                .Where(f => f.ScanIds.Contains(scan.Id))
                .ToList();

            var groups = SecurityScoreCalculator.BuildFindingGroups(scanFindings, discoveryAssetTypes);
            historicalScores.Add(SecurityScoreCalculator.CalculateScore(groups, scan.CreatedAt));
        }

        if (historicalScores.Count == 0)
            return 0;

        var averageHistoricalScore = (int)Math.Round(historicalScores.Average());

        var currentScanFindings = allFindings
            .Where(f => f.ScanIds.Contains(scansList[0].Id) && f.Status == "open")
            .ToList();

        var currentGroups = SecurityScoreCalculator.BuildFindingGroups(currentScanFindings, discoveryAssetTypes);
        var currentScore = SecurityScoreCalculator.CalculateScore(currentGroups, DateTime.UtcNow);

        return currentScore - averageHistoricalScore;
    }

    private static SecurityScoreResult MapToResult(SecurityScoreCalculation calculation, int trend)
    {
        return new SecurityScoreResult
        {
            Score = calculation.Score,
            TotalRisk = calculation.TotalRisk,
            Trend = trend,
            Breakdown = calculation.Breakdown,
            Summary = calculation.Summary,
            AppliedCap = calculation.AppliedCap
        };
    }
}
