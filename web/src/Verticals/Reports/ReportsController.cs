using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using MongoDB.Driver;
using VulWall.Dashboard.Attributes;
using VulWall.Dashboard.Common.Contracts.Enums;
using VulWall.Dashboard.Common.Services;
using VulWall.Dashboard.Common.Services.Organization;
using VulWall.Dashboard.Common.Services.RateLimiter;
using VulWall.Dashboard.Data.Repositories;
using VulWall.Dashboard.Reports.Models;
using VulWall.Dashboard.Reports.Services;
using VulWall.Dashboard.Reports.Services.SharedLinkService;
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
    SharedLinkService sharedLinkService,
    SharedLinksPublicRepository sharedLinksPublicRepository,
    IpRateLimiterService rateLimiter,
    IFeatureAccessService featureAccessService,
    ISuppressionFilter suppressionFilter)
    : Controller
{
    public async Task<IActionResult> Index()
    {
        var orgId = await organizationContext.GetCurrentOrgIdAsync();
        var featureAccess = await featureAccessService.GetFeatureAccessAsync();

        var organization = await organizationRepository.GetByIdAsync(orgId);
        var certVisible = organization?.CertVisible ?? true;

        var scans = await scansRepository.GetAllAsync();
        var rawFindings = await findingsRepository.GetAllAsync();
        var allDiscoveries = await discoveriesRepository.GetAllAsync();

        // Exclude actively-suppressed (discoveryId, findingType) pairs, matching Summary/Technical.
        var suppressedKeys = await suppressionFilter.GetActiveSuppressionKeysAsync();
        var allFindings = suppressionFilter.FilterSuppressed(rawFindings, suppressedKeys).ToList();

        var scanItems = await reportsService.BuildScanSelectItemsAsync(scans, allFindings, allDiscoveries);

        var sharedLinks = await sharedLinkService.GetSharedLinksAsync();
        var activeLinksCount = await sharedLinkService.GetActiveLinksCountAsync();

        var model = new IndexViewModel
        {
            SharedLinks = sharedLinks,
            ActiveLinksCount = activeLinksCount,
            MaxLinksCount = 5,
            OrganizationId = orgId,
            CompanyName = organization?.CompanyName ?? "Organization",
            CertVisible = certVisible,
            Scans = scanItems,
            SelectedScanId = scanItems.FirstOrDefault()?.Id,
            FeatureAccess = featureAccess
        };

        return View(model);
    }

    public async Task<IActionResult> Summary(string? scanId = null)
    {
        try
        {
            var orgId = await organizationContext.GetCurrentOrgIdAsync();
            var featureAccess = await featureAccessService.GetFeatureAccessAsync();

            var organization = await organizationRepository.GetByIdAsync(orgId);
            if (organization == null)
            {
                return NotFound("Organization not found");
            }

            var allFindingsRaw = (await findingsRepository.GetAllAsync()).ToList();
            var allDiscoveries = await discoveriesRepository.GetAllAsync();
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
                featureAccess,
                allDoneScans,
                allFindings,
                previousScan?.Id,
                allDiscoveries,
                organization.Logo
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
            var featureAccess = await featureAccessService.GetFeatureAccessAsync();
            var orgId = await organizationContext.GetCurrentOrgIdAsync();

            var organization = await organizationRepository.GetByIdAsync(orgId);
            if (organization == null)
            {
                return NotFound("Organization not found");
            }

            var allFindingsRaw = (await findingsRepository.GetAllAsync()).ToList();
            var allDiscoveries = await discoveriesRepository.GetAllAsync();
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
                featureAccess,
                organization.Logo
            );

            return View(model);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Error loading technical report");
            return StatusCode(500, "Error loading report data");
        }
    }

    [HttpPost]
    [AuditLog(Category = AuditLogCategory.Reports, Action = "Certificate visibility updated")]
    public async Task<IActionResult> UpdateCertVisibility([FromBody] bool isVisible)
    {
        var featureAccess = await featureAccessService.GetFeatureAccessAsync();
        if (!featureAccess.CanPublishCertificate)
        {
            return BadRequest(new { success = false, error = "Publishing the certificate is not enabled" });
        }

        var orgId = await organizationContext.GetCurrentOrgIdAsync();
        var organization = await organizationRepository.GetByIdAsync(orgId);

        if (organization == null)
        {
            return NotFound("Organization not found");
        }

        var previousStatus = organization.CertVisible;
        organization.CertVisible = isVisible;
        organization.UpdatedAt = DateTime.UtcNow;

        await organizationRepository.UpdateAsync(organization);

        logger.LogInformation("Updated certificate visibility for organization: {OrgId} from {PreviousStatus} to {NewStatus}",
            orgId, previousStatus, isVisible);

        HttpContext.Items["AuditLogAdditionalInfo"] = isVisible ? "enabled certificate" : "disabled certificate";

        return Ok(new { success = true, certVisible = isVisible });
    }

    [AllowAnonymous]
    [Route("/certs/{orgId}")]
    public async Task<IActionResult> Cert(string orgId)
    {
        if (!ObjectId.TryParse(orgId, out _))
        {
            return NotFound();
        }

        var organization = await organizationRepository.GetByIdAsync(orgId);
        if (organization == null)
        {
            return View("CertNotAvailable");
        }

        var certUrl = $"{Request.Scheme}://{Request.Host}/certs/{orgId}";
        var model = await reportsService.BuildPublicCertificateViewModel(orgId, certUrl);

        return model == null ? View("CertNotAvailable") : View(model);
    }

    [AllowAnonymous]
    [Route("/certs/{orgId}/logo")]
    public async Task<IActionResult> GetOrgLogo(string orgId)
    {
        var organization = await organizationRepository.GetByIdAsync(orgId);

        if (organization?.Logo == null || organization.Logo.Length == 0)
        {
            return NotFound();
        }

        return File(organization.Logo, "image/png");
    }

    [AllowAnonymous]
    [Route("/certs/{orgId}/embed")]
    public async Task<IActionResult> CertEmbed(string orgId)
    {
        if (!ObjectId.TryParse(orgId, out _))
        {
            return NotFound();
        }

        var organization = await organizationRepository.GetByIdAsync(orgId);

        if (organization == null || !organization.CertVisible)
        {
            return View("CertEmbedDisabled");
        }

        var certUrl = $"{Request.Scheme}://{Request.Host}/certs/{orgId}";
        var model = await reportsService.BuildPublicCertificateViewModel(orgId, certUrl);

        if (model == null)
        {
            return View("CertEmbedDisabled");
        }

        return View(model);
    }

    [HttpPost]
    [AuditLog(Category = AuditLogCategory.Reports, Action = "Shared link created")]
    public async Task<IActionResult> CreateSharedLink([FromBody] CreateSharedLinkRequest request)
    {
        var featureAccess = await featureAccessService.GetFeatureAccessAsync();
        if (!featureAccess.CanShareReports)
        {
            return BadRequest(new CreateSharedLinkResponse
            {
                Success = false,
                Error = "Sharing reports is not enabled"
            });
        }

        var (link, error) = await sharedLinkService.CreateSharedLinkAsync(
            request.ReportName,
            request.ScanId,
            request.Password,
            request.ExpirationDays);

        if (link == null)
        {
            return BadRequest(new CreateSharedLinkResponse
            {
                Success = false,
                Error = error
            });
        }

        var shareableUrl = $"{Request.Scheme}://{Request.Host}/shared-reports/{link.Token}";

        HttpContext.Items["AuditLogAdditionalInfo"] = $"created shared link: {request.ReportName}";

        return Ok(new CreateSharedLinkResponse
        {
            Success = true,
            LinkId = link.Id,
            Token = link.Token,
            ShareableUrl = shareableUrl
        });
    }

    [HttpPost]
    [AuditLog(Category = AuditLogCategory.Reports, Action = "Shared link revoked")]
    public async Task<IActionResult> RevokeSharedLink([FromBody] string linkId)
    {
        var result = await sharedLinkService.RevokeSharedLinkAsync(linkId);

        if (!result)
        {
            return NotFound(new { success = false, error = "Link not found" });
        }

        HttpContext.Items["AuditLogAdditionalInfo"] = $"revoked shared link: {linkId}";

        return Ok(new { success = true });
    }

    [AllowAnonymous]
    [IgnoreAntiforgeryToken]
    [Route("/shared-reports/{token}")]
    public async Task<IActionResult> SharedReport(string token, [FromForm] string? password = null)
    {
        const string endpoint = "shared-reports";

        var link = await sharedLinkService.GetSharedLinkByTokenAsync(token);

        if (link == null)
        {
            return View(new SharedReportViewModel { NotFound = true });
        }

        if (link.IsRevoked)
        {
            return View(new SharedReportViewModel { IsRevoked = true, Token = token });
        }

        if (link.IsExpired)
        {
            return View(new SharedReportViewModel { IsExpired = true, Token = token });
        }

        // If no password provided, show password form
        if (string.IsNullOrEmpty(password))
        {
            return View(new SharedReportViewModel { RequiresPassword = true, Token = token });
        }

        // Check rate limiting before verifying password. Failures count against both the caller's
        // IP and the link token, so rotating IPs does not allow unlimited guesses on one link.
        if (rateLimiter.IsRateLimited(endpoint) || rateLimiter.IsRateLimited(endpoint, token))
        {
            return View(new SharedReportViewModel
            {
                RequiresPassword = true,
                Token = token,
                ErrorMessage = "Too many failed attempts. Please try again in 15 minutes."
            });
        }

        // Verify password
        var isValidPassword = await sharedLinkService.VerifyPasswordAsync(token, password);
        if (!isValidPassword)
        {
            rateLimiter.RecordAttempt(endpoint);
            rateLimiter.RecordAttempt(endpoint, token);
            var remaining = Math.Min(
                rateLimiter.GetRemainingAttempts(endpoint),
                rateLimiter.GetRemainingAttempts(endpoint, token));

            return View(new SharedReportViewModel
            {
                RequiresPassword = true,
                Token = token,
                ErrorMessage = remaining > 0
                    ? $"Invalid password. {remaining} attempt(s) remaining."
                    : "Too many failed attempts. Please try again in 15 minutes."
            });
        }

        // Password correct - reset only this link's counter. The IP counter is left to expire so
        // a correct password on one link (e.g. the attacker's own) cannot clear failures on another.
        rateLimiter.ResetAttempts(endpoint, token);

        // Password correct - build and show report
        var organization = await organizationRepository.GetByIdAsync(link.OrgId);
        if (organization == null)
        {
            return View(new SharedReportViewModel { NotFound = true });
        }

        // Get all org findings (across every scan) - use public repository to bypass org scoping.
        // The full set powers the score trend and since-last-scan delta; the report itself is then
        // scoped to the linked scan below.
        var orgFindingsRaw = await sharedLinksPublicRepository.Database
            .GetCollection<Data.Entities.Finding.Finding>("findings")
            .Find(f => f.OrgId == link.OrgId)
            .ToListAsync();

        var allDiscoveries = await sharedLinksPublicRepository.Database
            .GetCollection<Data.Entities.Discovery.Discovery>("discoveries")
            .Find(d => d.OrgId == link.OrgId && d.ScanIds != null && d.ScanIds.Contains(link.ScanId))
            .ToListAsync();

        var scan = await sharedLinksPublicRepository.Database
            .GetCollection<Data.Entities.Scan.Scan>("scans")
            .Find(s => s.Id == link.ScanId)
            .FirstOrDefaultAsync();

        var orgDoneScans = await sharedLinksPublicRepository.Database
            .GetCollection<Data.Entities.Scan.Scan>("scans")
            .Find(s => s.OrgId == link.OrgId && s.Status == ScanStatus.Done)
            .ToListAsync();

        // Exclude actively-suppressed findings from shared reports, same as authenticated paths.
        // Uses the public (non-org-scoped) key lookup because this endpoint is anonymous.
        var suppressedKeys = await suppressionFilter.GetActiveSuppressionKeysForOrgAsync(link.OrgId);
        var allFindings = suppressionFilter.FilterSuppressed(orgFindingsRaw, suppressedKeys).ToList();
        var scanFindings = allFindings.Where(f => f.ScanIds.Contains(link.ScanId)).ToList();

        var previousScan = scan == null
            ? null
            : orgDoneScans
                .Where(s => s.Id != scan.Id && s.CreatedAt < scan.CreatedAt)
                .OrderByDescending(s => s.CreatedAt)
                .FirstOrDefault();

        // Shared reports always render full report content
        var sharedFeatureAccess = Common.Models.FeatureAccess.Full;

        var report = await summaryReportBuilder.BuildReportAsync(
            link.OrgId,
            organization.CompanyName ?? "Unknown Organization",
            scanFindings,
            allDiscoveries,
            scan,
            sharedFeatureAccess,
            orgDoneScans,
            allFindings,
            previousScan?.Id,
            allDiscoveries,
            organization.Logo
        );

        return View(new SharedReportViewModel
        {
            Report = report,
            Token = token
        });
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