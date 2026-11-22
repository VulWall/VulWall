using VulWall.Dashboard.Common.Services;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Data.Entities.Scan;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Reports.Services.ReportGeneration;

namespace VulWall.Dashboard.Reports.Services.ExecutiveSummaryJob;

/// <summary>
/// Writes the AI executive summary onto finished scans, once per scan. Each scan is claimed
/// atomically, so several app instances can run this without doing the same scan twice.
/// Without ANTHROPIC_API_KEY the scan is marked "skipped" and the report renders without
/// the AI section; once a key is set, skipped scans of the last 7 days are summarized. A failed
/// attempt is retried with backoff, up to ScansPublicRepository.MaxExecutiveSummaryAttempts.
/// </summary>
public class ExecutiveSummaryProcessor(
    ScansPublicRepository scansRepository,
    FindingsPublicRepository findingsRepository,
    DiscoveriesPublicRepository discoveriesRepository,
    KnowledgeBaseCacheService knowledgeBaseCache,
    ExecutiveSummaryService executiveSummaryService,
    IAssetScopeFilter assetScopeFilter,
    ILogger<ExecutiveSummaryProcessor> logger)
{
    private static readonly TimeSpan MaxScanAge = TimeSpan.FromDays(7);
    private static readonly TimeSpan StaleClaimAfter = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Processes every claimable scan and returns how many were handled.
    /// </summary>
    public async Task<int> ProcessPendingAsync(bool aiEnabled, CancellationToken cancellationToken)
    {
        var processed = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            var scan = await scansRepository.ClaimNextForExecutiveSummaryAsync(
                DateTime.UtcNow - MaxScanAge, StaleClaimAfter, aiEnabled);
            if (scan is null)
                break;

            var status = aiEnabled
                ? await GenerateAsync(scan, cancellationToken)
                : ExecutiveSummaryStatus.Skipped;
            if (status != ExecutiveSummaryStatus.Done)
                await scansRepository.CompleteExecutiveSummaryAsync(scan.Id, status);

            processed++;
        }

        return processed;
    }

    private async Task<string> GenerateAsync(Scan scan, CancellationToken cancellationToken)
    {
        try
        {
            // Disabled assets' data is left out, as in the report the summary goes with.
            var scope = await assetScopeFilter.GetAsync(scan.OrgId);
            var findings = scope.Filter(await findingsRepository.FindAsync(f => f.ScanIds.Contains(scan.Id)));
            var kbByType = (await knowledgeBaseCache.GetAllAsync()).ToDictionary(kb => kb.FindingType, kb => kb);

            // Same score path as SummaryReportBuilder, so the summary matches the report.
            var discoveries = scope.Filter(await discoveriesRepository.FindAsync(d => d.OrgId == scan.OrgId));
            var discoveryAssetTypes = discoveries.ToDictionary(d => d.Id, d => d.AssetType);
            var findingGroups = SecurityScoreCalculator.BuildFindingGroups(findings, discoveryAssetTypes);
            var securityPosture = SecurityScoreCalculator.Calculate(findingGroups, DateTime.UtcNow).Summary.Status;

            var summary = await executiveSummaryService.GenerateExecutiveSummaryAsync(
                securityPosture, findings, kbByType, cancellationToken);

            if (string.IsNullOrWhiteSpace(summary))
            {
                logger.LogWarning("AI executive summary was empty for scan {ScanId}", scan.Id);
                return ExecutiveSummaryStatus.Failed;
            }

            await scansRepository.CompleteExecutiveSummaryAsync(scan.Id, ExecutiveSummaryStatus.Done, summary);
            logger.LogInformation("Persisted AI executive summary for scan {ScanId}", scan.Id);
            return ExecutiveSummaryStatus.Done;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Failed to generate executive summary for scan {ScanId}", scan.Id);
            return ExecutiveSummaryStatus.Failed;
        }
    }
}
