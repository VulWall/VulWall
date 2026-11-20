using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services;
using VulWall.Dashboard.Common.Services.Email;
using VulWall.Dashboard.Common.Utils;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Reports.Services.ReportGeneration;

namespace VulWall.Dashboard.Webhooks.Services;

public class NightWatchWebhookService(
    ScansPublicRepository scansRepository,
    FindingsPublicRepository findingsRepository,
    DiscoveriesPublicRepository discoveriesRepository,
    OrganizationRepository organizationRepository,
    KnowledgeBaseCacheService knowledgeBaseCache,
    ExecutiveSummaryService executiveSummaryService,
    IEmailService emailService,
    IHttpContextAccessor httpContextAccessor,
    ILogger<NightWatchWebhookService> logger)
{
    public async Task HandleScanCompletedAsync(string scanId)
    {
        var scan = await scansRepository.GetByIdAsync(scanId);
        if (scan is null)
        {
            logger.LogWarning("Webhook received for unknown scan {ScanId}", scanId);
            return;
        }

        var org = await organizationRepository.GetByIdAsync(scan.OrgId);
        if (org is null || string.IsNullOrWhiteSpace(org.OwnerEmail))
        {
            logger.LogWarning("No owner email found for organization {OrgId}, skipping scan completion email", scan.OrgId);
            return;
        }

        var findingsList = (await findingsRepository.FindAsync(f => f.ScanIds.Contains(scanId))).ToList();

        var (critical, high, medium, low) = FindingSeverityCounter.CountBySeverityGrouped(findingsList);
        var totalFindings = critical + high + medium + low;
        var (criticalRaw, highRaw, mediumRaw, lowRaw) = FindingSeverityCounter.CountBySeverityRaw(findingsList);
        var totalInstances = criticalRaw + highRaw + mediumRaw + lowRaw;

        var orgName = !string.IsNullOrWhiteSpace(org.CompanyName)
            ? org.CompanyName
            : "your organization";

        var duration = scan.CompletedAt.HasValue
            ? FormatDuration(scan.CompletedAt.Value - scan.CreatedAt)
            : "N/A";

        var request = httpContextAccessor.HttpContext?.Request;
        var baseUrl = request is not null ? $"{request.Scheme}://{request.Host}" : "";

        var variables = new Dictionary<string, object>
        {
            ["orgName"] = orgName,
            ["totalFindings"] = totalFindings.ToString(),
            ["totalInstances"] = totalInstances.ToString(),
            ["critical"] = critical.ToString(),
            ["criticalInstances"] = criticalRaw.ToString(),
            ["high"] = high.ToString(),
            ["highInstances"] = highRaw.ToString(),
            ["medium"] = medium.ToString(),
            ["mediumInstances"] = mediumRaw.ToString(),
            ["low"] = low.ToString(),
            ["lowInstances"] = lowRaw.ToString(),
            ["scanType"] = scan.Type.ToString(),
            ["duration"] = duration,
            ["completedAt"] = scan.CompletedAt?.ToString("MMMM dd, yyyy 'at' hh:mm tt UTC") ?? "N/A",
            ["dashboardUrl"] = $"{baseUrl}/Scans",
            ["settingsUrl"] = $"{baseUrl}/Settings"
        };

        var scanSubject = $"Scan Result {(scan.CompletedAt ?? DateTime.UtcNow):MMMM dd, yyyy}";
        var sent = await emailService.SendTemplateAsync(org.OwnerEmail, EmailTemplate.ScanComplete, variables, scanSubject);
        if (sent)
            logger.LogInformation("Scan completion email sent to {Email} for scan {ScanId}", org.OwnerEmail, scanId);
        else
            logger.LogWarning("Failed to send scan completion email to {Email} for scan {ScanId}", org.OwnerEmail, scanId);

        // Generate and persist AI executive summary — fire-and-forget so webhook returns fast
        _ = Task.Run(() => GenerateAndPersistExecutiveSummaryAsync(scanId, scan.OrgId, findingsList));
    }

    private async Task GenerateAndPersistExecutiveSummaryAsync(
        string scanId,
        string orgId,
        List<Data.Entities.Finding.Finding> findingsList)
    {
        try
        {
            var kbEntries = await knowledgeBaseCache.GetAllAsync();
            var kbByType = kbEntries.ToDictionary(kb => kb.FindingType, kb => kb);

            // Load discoveries to calculate security score (same path as SummaryReportBuilder)
            var discoveries = (await discoveriesRepository.FindAsync(d => d.OrgId == orgId)).ToList();
            var discoveryAssetTypes = discoveries.ToDictionary(d => d.Id, d => d.AssetType);
            var findingGroups = SecurityScoreCalculator.BuildFindingGroups(findingsList, discoveryAssetTypes);
            var scoreResult = SecurityScoreCalculator.Calculate(findingGroups, DateTime.UtcNow);
            var securityPosture = scoreResult.Summary.Status;

            var summary = await executiveSummaryService.GenerateExecutiveSummaryAsync(
                securityPosture,
                findingsList,
                kbByType);

            if (!string.IsNullOrWhiteSpace(summary))
            {
                await scansRepository.UpdateExecutiveSummaryAsync(scanId, summary);
                logger.LogInformation("Persisted AI executive summary for scan {ScanId}", scanId);
            }
            else
            {
                logger.LogWarning("AI executive summary was empty for scan {ScanId}, skipping persistence", scanId);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to generate/persist executive summary for scan {ScanId}. Report will fall back to on-demand generation.", scanId);
        }
    }

    private static string FormatDuration(TimeSpan duration)
    {
        if (duration.TotalHours >= 1)
            return $"{(int)duration.TotalHours}h {duration.Minutes}m";
        if (duration.TotalMinutes >= 1)
            return $"{(int)duration.TotalMinutes}m {duration.Seconds}s";
        return $"{(int)duration.TotalSeconds}s";
    }
}
