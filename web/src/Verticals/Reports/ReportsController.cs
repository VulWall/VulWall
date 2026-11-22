using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Reports.Models;
using VulWall.Dashboard.Reports.Services;
using SummaryReportBuilder = VulWall.Dashboard.Reports.Services.ReportGeneration.SummaryReportBuilder;
using TechnicalReportBuilder = VulWall.Dashboard.Reports.Services.ReportGeneration.TechnicalReportBuilder;

namespace VulWall.Dashboard.Reports;

[Authorize]
public class ReportsController(
    ILogger<ReportsController> logger,
    OrganizationRepository organizationRepository,
    IOrganizationContext organizationContext,
    SummaryReportBuilder summaryReportBuilder,
    TechnicalReportBuilder technicalReportBuilder,
    FindingsRepository findingsRepository,
    DiscoveriesRepository discoveriesRepository,
    ScansRepository scansRepository,
    ReportsService reportsService,
    ISuppressionFilter suppressionFilter,
    IAssetScopeFilter assetScopeFilter)
    : Controller
{
    public async Task<IActionResult> Index()
    {
        var scans = await scansRepository.GetAllAsync();
        var scope = await assetScopeFilter.GetAsync(await organizationContext.GetCurrentOrgIdAsync());
        var rawFindings = scope.Filter(await findingsRepository.GetAllAsync());
        var allDiscoveries = scope.Filter(await discoveriesRepository.GetAllAsync());

        // Exclude actively-suppressed (discoveryId, findingType) pairs, matching Summary/Technical.
        var suppressedKeys = await suppressionFilter.GetActiveSuppressionKeysAsync();
        var allFindings = suppressionFilter.FilterSuppressed(rawFindings, suppressedKeys).ToList();

        var scanItems = await reportsService.BuildScanSelectItemsAsync(scans, allFindings, allDiscoveries);

        var model = new IndexViewModel
        {
            Scans = scanItems,
            SelectedScanId = scanItems.FirstOrDefault()?.Id
        };

        return View(model);
    }

    public async Task<IActionResult> Summary(string? scanId = null)
    {
        try
        {
            var orgId = await organizationContext.GetCurrentOrgIdAsync();

            var organization = await organizationRepository.GetByIdAsync(orgId);
            if (organization == null)
            {
                return NotFound("Organization not found");
            }

            var scope = await assetScopeFilter.GetAsync(orgId);
            var allFindingsRaw = scope.Filter(await findingsRepository.GetAllAsync());
            var allDiscoveries = scope.Filter(await discoveriesRepository.GetAllAsync());
            var scans = await scansRepository.GetAllAsync();
            var suppressedKeys = await suppressionFilter.GetActiveSuppressionKeysAsync();

            // Exclude actively-suppressed (discoveryId, findingType) pairs from reports
            var allFindings = suppressionFilter.FilterSuppressed(allFindingsRaw, suppressedKeys).ToList();

            // Resolve the target scan and filter both findings and discoveries to it
            var findings = allFindings;
            Data.Entities.Scan.Scan? selectedScan = null;

            if (!string.IsNullOrEmpty(scanId))
            {
                selectedScan = scans.FirstOrDefault(s => s.Id == scanId);
            }
            else
            {
                selectedScan = scans.Where(s => s.Status == ScanStatus.Done).OrderByDescending(s => s.CreatedAt).FirstOrDefault();
            }

            if (selectedScan != null)
            {
                findings = allFindings.Where(f => f.ScanIds.Contains(selectedScan.Id)).ToList();
            }

            var discoveries = FilterDiscoveriesByScanId(allDiscoveries, selectedScan?.Id);

            var allDoneScans = scans.Where(s => s.Status == ScanStatus.Done).ToList();
            var previousScan = selectedScan == null
                ? null
                : allDoneScans
                    .Where(s => s.Id != selectedScan.Id && s.CreatedAt < selectedScan.CreatedAt)
                    .OrderByDescending(s => s.CreatedAt)
                    .FirstOrDefault();

            var model = await summaryReportBuilder.BuildReportAsync(
                orgId,
                organization.CompanyName ?? "Unknown Organization",
                findings,
                discoveries,
                selectedScan,
                allDoneScans,
                allFindings,
                previousScan?.Id,
                allDiscoveries,
                organization.Logo,
                organization.GetLogoContentType()
            );

            return View(model);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error loading summary report");
            return StatusCode(500, "Error loading report data");
        }
    }

    public async Task<IActionResult> Technical(string? scanId = null)
    {
        try
        {
            var orgId = await organizationContext.GetCurrentOrgIdAsync();

            var organization = await organizationRepository.GetByIdAsync(orgId);
            if (organization == null)
            {
                return NotFound("Organization not found");
            }

            var scope = await assetScopeFilter.GetAsync(orgId);
            var allFindingsRaw = scope.Filter(await findingsRepository.GetAllAsync());
            var allDiscoveries = scope.Filter(await discoveriesRepository.GetAllAsync());
            var scans = await scansRepository.GetAllAsync();
            var suppressedKeys = await suppressionFilter.GetActiveSuppressionKeysAsync();

            // Exclude actively-suppressed (discoveryId, findingType) pairs from reports
            var allFindings = suppressionFilter.FilterSuppressed(allFindingsRaw, suppressedKeys).ToList();

            // Resolve the target scan and filter both findings and discoveries to it
            var findings = allFindings;
            Data.Entities.Scan.Scan? selectedScan = null;

            if (!string.IsNullOrEmpty(scanId))
            {
                selectedScan = scans.FirstOrDefault(s => s.Id == scanId);
            }
            else
            {
                selectedScan = scans.Where(s => s.Status == ScanStatus.Done).OrderByDescending(s => s.CreatedAt).FirstOrDefault();
            }

            if (selectedScan != null)
            {
                findings = allFindings.Where(f => f.ScanIds.Contains(selectedScan.Id)).ToList();
            }

            var discoveries = FilterDiscoveriesByScanId(allDiscoveries, selectedScan?.Id);

            var model = await technicalReportBuilder.BuildReportAsync(
                orgId,
                organization.CompanyName ?? "Unknown Organization",
                findings,
                discoveries,
                selectedScan,
                organization.Logo,
                organization.GetLogoContentType()
            );

            return View(model);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error loading technical report");
            return StatusCode(500, "Error loading report data");
        }
    }

    /// <summary>
    /// Filters discoveries to only those that participated in the given scan.
    /// Returns all discoveries as a graceful fallback when no scan ID is available.
    /// </summary>
    private static List<Data.Entities.Discovery.Discovery> FilterDiscoveriesByScanId(
        IEnumerable<Data.Entities.Discovery.Discovery> discoveries,
        string? scanId)
    {
        if (scanId == null)
            return discoveries.ToList();

        return discoveries
            .Where(d => d.ScanIds != null && d.ScanIds.Contains(scanId))
            .ToList();
    }
}